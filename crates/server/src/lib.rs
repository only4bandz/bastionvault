//! **Zero-knowledge** sync server.
//!
//! It never sees the master password, the Secret Key, or any item in cleartext.
//! It stores only:
//! - the public registration data (`salt`, `kdf`, wrapped vault key);
//! - a **slow Argon2id hash** of the authentication secret (never the raw secret);
//! - the items and the manifest, as opaque [`EncryptedBlob`]s.
//!
//! Durability: data is persisted to **SQLite** (still zero-knowledge — only
//! opaque blobs and the auth-secret hash are stored). An in-memory cache backs
//! the reads and is loaded from SQLite at startup; mutations are write-through.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params as ArgonParams};
use axum::extract::{DefaultBodyLimit, Extension, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crypto_core::{AuthSecret, EncryptedBlob, KdfParams, PublicIdentity, Registration, SendBlob};

/// Default session token lifetime (30 min).
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// Maximum request body size (1 MiB) — guardrail against memory DoS.
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_ACCOUNT_ID_BYTES: usize = 254;
const AUTH_SECRET_BYTES: usize = 32;
const AUTH_HASH_SALT_BYTES: usize = 16;
const AUTH_HASH_OUTPUT_BYTES: usize = 32;
const REGISTRATION_SALT_BYTES: usize = 16;
const WRAPPED_KEY_NONCE_BYTES: usize = 24;
const WRAPPED_KEY_CIPHERTEXT_BYTES: usize = 48;
/// Per-account vault quotas. These bound SQLite growth, the in-memory cache,
/// and the size of a full `/vault` response independently of request size.
const MAX_VAULT_ITEMS: usize = 10_000;
const MAX_VAULT_BYTES: usize = 64 * 1024 * 1024;
const MAX_VAULT_BLOB_BYTES: usize = 512 * 1024;
/// A 10,000-entry encrypted manifest can legitimately exceed the per-item
/// limit, especially when item ids approach their maximum length.
const MAX_VAULT_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
/// A transaction carries one complete sealed manifest plus a bounded batch of
/// item operations. Authentication middleware runs before this larger body is
/// extracted, so unauthenticated callers retain the global 1 MiB limit.
const MAX_VAULT_TRANSACTION_BODY_BYTES: usize =
    MAX_VAULT_MANIFEST_BYTES + (3 * MAX_VAULT_BLOB_BYTES) + (64 * 1024);
const MAX_VAULT_TRANSACTION_OPS: usize = 256;
const MAX_ITEM_ID_BYTES: usize = 256;
const MAX_CONCURRENT_AUTH: usize = 4;
const MAX_SESSIONS_PER_ACCOUNT: usize = 8;
const MAX_ACTIVE_SESSIONS: usize = 100_000;
const MAX_AUTH_RATE_ENTRIES: usize = 10_000;
const MAX_ACCOUNT_CREATIONS_GLOBAL_PER_MIN: u32 = 20;
const MAX_ACCOUNT_CREATIONS_PER_ACCOUNT_PER_MIN: u32 = 2;
const MAX_LOGIN_ATTEMPTS_GLOBAL_PER_MIN: u32 = 120;
const MAX_LOGIN_ATTEMPTS_PER_ACCOUNT_PER_MIN: u32 = 10;
// Prelogin is unauthenticated and reveals whether an account exists (plus its
// KDF params), so it gets its own throttle against bulk enumeration.
const MAX_PRELOGINS_GLOBAL_PER_MIN: u32 = 300;
const MAX_PRELOGINS_PER_ACCOUNT_PER_MIN: u32 = 15;
/// Bastion Send: max stored blob size, per-recipient inbox cap, and per-account
/// fixed-window rate limits (abuse controls — see docs/bastion-send-design.md §8).
const MAX_SEND_BLOB: usize = 256 * 1024;
const MAX_SEND_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_INBOX: i64 = 500;
const MAX_INBOX_PAGE: i64 = 100; // cap a single inbox fetch (paginate by deleting)
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_SENDS_PER_MIN: u32 = 60; // per sender
const MAX_INBOUND_PER_MIN: u32 = 120; // per recipient (anti inbox-flood)
const MAX_LOOKUPS_PER_MIN: u32 = 120;
// Authenticated read throttles: a full vault read clones and re-serializes up
// to MAX_VAULT_BYTES per call, and an inbox read runs a purge + list — both
// are cheap amplification levers for a hostile-but-authenticated client.
const MAX_VAULT_READS_PER_MIN: u32 = 60;
const MAX_INBOX_READS_PER_MIN: u32 = 60;
const MAX_RATE_ENTRIES: usize = 100_000; // bound the in-memory rate map (anti memory-DoS)

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn valid_bastion_id(id: &str) -> bool {
    if id.len() != 26 {
        return false;
    }
    data_encoding::BASE32_NOPAD
        .decode(id.as_bytes())
        .ok()
        .filter(|decoded| decoded.len() == 16)
        .is_some_and(|decoded| data_encoding::BASE32_NOPAD.encode(&decoded) == id)
}

fn valid_message_id(id: &str) -> bool {
    if id.len() != 24 {
        return false;
    }
    B64.decode(id)
        .ok()
        .filter(|decoded| decoded.len() == 16)
        .is_some_and(|decoded| B64.encode(&decoded) == id)
}

fn stored_data_error(
    column: usize,
    data_type: rusqlite::types::Type,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, data_type, Box::new(error))
}

/// Builds the router, persisting to the SQLite database at `$BASTION_DB`
/// (default `bastion.db` in the working directory).
///
/// ⚠️ NON-PRODUCTION: this server still has NO TLS or CORS. The Bastion Send
/// endpoints have per-account rate limits + inbox quotas + size caps. Vault
/// writes also have per-item, item-count, and aggregate encrypted-byte quotas.
/// Add TLS/CORS and broader rate limiting before deployment.
pub fn app() -> Router {
    let db_path = std::env::var("BASTION_DB").unwrap_or_else(|_| "bastion.db".to_string());
    build(DEFAULT_TOKEN_TTL, &db_path, MAX_CONCURRENT_AUTH)
}

/// Variant with an explicit SQLite path (used to test persistence).
pub fn app_with_db(db_path: &str) -> Router {
    build(DEFAULT_TOKEN_TTL, db_path, MAX_CONCURRENT_AUTH)
}

/// In-memory (non-persistent) variant — used by tests for isolation.
pub fn app_in_memory() -> Router {
    build(DEFAULT_TOKEN_TTL, ":memory:", MAX_CONCURRENT_AUTH)
}

/// In-memory variant with an explicit TTL (tests for token expiration).
pub fn app_in_memory_with_ttl(token_ttl: Duration) -> Router {
    build(token_ttl, ":memory:", MAX_CONCURRENT_AUTH)
}

/// In-memory variant with an explicit authentication concurrency limit. A zero
/// limit is useful for deterministic overload tests.
pub fn app_in_memory_with_auth_limit(auth_limit: usize) -> Router {
    build(DEFAULT_TOKEN_TTL, ":memory:", auth_limit)
}

/// In-memory variant with explicit rate-state bounds for deterministic tests.
pub fn app_in_memory_with_rate_limits(max_entries: usize, window: Duration) -> Router {
    build_with_rate_limits(
        DEFAULT_TOKEN_TTL,
        ":memory:",
        MAX_CONCURRENT_AUTH,
        max_entries,
        window,
        AuthRateLimits::default(),
    )
}

/// Authentication rate policy override used by deterministic integration
/// tests and embedders that need stricter process-local limits.
#[derive(Clone, Copy, Debug)]
pub struct AuthRateLimits {
    pub max_entries: usize,
    pub window: Duration,
    pub account_creations_global: u32,
    pub account_creations_per_account: u32,
    pub login_attempts_global: u32,
    pub login_attempts_per_account: u32,
    pub prelogins_global: u32,
    pub prelogins_per_account: u32,
}

impl Default for AuthRateLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_AUTH_RATE_ENTRIES,
            window: RATE_WINDOW,
            account_creations_global: MAX_ACCOUNT_CREATIONS_GLOBAL_PER_MIN,
            account_creations_per_account: MAX_ACCOUNT_CREATIONS_PER_ACCOUNT_PER_MIN,
            login_attempts_global: MAX_LOGIN_ATTEMPTS_GLOBAL_PER_MIN,
            login_attempts_per_account: MAX_LOGIN_ATTEMPTS_PER_ACCOUNT_PER_MIN,
            prelogins_global: MAX_PRELOGINS_GLOBAL_PER_MIN,
            prelogins_per_account: MAX_PRELOGINS_PER_ACCOUNT_PER_MIN,
        }
    }
}

/// In-memory variant with an explicit authentication rate policy.
pub fn app_in_memory_with_auth_rate_limits(limits: AuthRateLimits) -> Router {
    build_with_rate_limits(
        DEFAULT_TOKEN_TTL,
        ":memory:",
        MAX_CONCURRENT_AUTH,
        MAX_RATE_ENTRIES,
        RATE_WINDOW,
        limits,
    )
}

fn build(token_ttl: Duration, db_path: &str, auth_limit: usize) -> Router {
    build_with_rate_limits(
        token_ttl,
        db_path,
        auth_limit,
        MAX_RATE_ENTRIES,
        RATE_WINDOW,
        AuthRateLimits::default(),
    )
}

fn build_with_rate_limits(
    token_ttl: Duration,
    db_path: &str,
    auth_limit: usize,
    max_rate_entries: usize,
    rate_window: Duration,
    auth_rate_limits: AuthRateLimits,
) -> Router {
    let state = AppState::new(
        token_ttl,
        db_path,
        auth_limit,
        max_rate_entries,
        rate_window,
        auth_rate_limits,
    );
    let transaction_route = put(apply_vault_transaction)
        .layer(DefaultBodyLimit::max(MAX_VAULT_TRANSACTION_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_vault_transaction,
        ));
    Router::new()
        .route("/health", get(health))
        .route("/accounts", post(create_account))
        .route("/accounts/:email/prelogin", get(prelogin))
        .route("/sessions", post(create_session).delete(delete_session))
        .route("/vault", get(get_vault))
        .route("/vault/items/:id", put(put_item).delete(delete_item))
        .route("/vault/manifest", put(put_manifest))
        .route("/vault/transaction", transaction_route)
        // ── Bastion Send ──
        .route("/send/identity", put(publish_identity))
        .route("/send/whoami", get(send_whoami))
        .route("/send/directory/:bastion_id", get(send_directory))
        .route("/send", post(send_post))
        .route("/send/inbox", get(send_inbox))
        .route(
            "/send/inbox/:message_id",
            axum::routing::delete(send_inbox_delete),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Stamps defensive headers on every response, including errors.
///
/// The API serves bearer tokens, wrapped vault keys and encrypted blobs; none
/// of it may ever land in a shared cache or be sniffed/framed by a browser.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

// ─── Shared state ───

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<Inner>>,
    db: Db,
    token_ttl: Duration,
    auth_slots: Arc<Semaphore>,
    max_rate_entries: usize,
    rate_window: Duration,
    auth_rate_limits: AuthRateLimits,
}

struct Inner {
    accounts: HashMap<String, AccountRecord>, // email -> account
    sessions: HashMap<String, Session>,       // token -> session
    rate: HashMap<String, RateState>,         // "email:bucket" -> fixed-window counter
    auth_rate: HashMap<String, RateState>,    // pre-Argon2 account/global counters
}

/// Fixed-window rate counter.
struct RateState {
    window_start: Instant,
    count: u32,
}

/// Active session: the token's owner and its expiration instant.
struct Session {
    email: String,
    created_at: Instant,
    expires_at: Instant,
}

/// Everything the server keeps about an account. Nothing here is decryptable.
struct AccountRecord {
    salt: String,
    kdf: KdfParams,
    wrapped_vault_key: EncryptedBlob,
    /// Argon2id hash (PHC) of the authentication secret.
    auth_hash: String,
    items: HashMap<String, EncryptedBlob>,
    item_bytes: HashMap<String, usize>,
    manifest: Option<EncryptedBlob>,
    manifest_bytes: usize,
    stored_bytes: usize,
    vault_revision: u64,
}

impl AppState {
    fn new(
        token_ttl: Duration,
        db_path: &str,
        auth_limit: usize,
        max_rate_entries: usize,
        rate_window: Duration,
        auth_rate_limits: AuthRateLimits,
    ) -> Self {
        let db = Db::open(db_path);
        let accounts = db.load_accounts().expect("load persisted vault state");
        Self {
            inner: Arc::new(RwLock::new(Inner {
                accounts,
                sessions: HashMap::new(),
                rate: HashMap::new(),
                auth_rate: HashMap::new(),
            })),
            db,
            token_ttl,
            auth_slots: Arc::new(Semaphore::new(auth_limit)),
            max_rate_entries,
            rate_window,
            auth_rate_limits,
        }
    }

    /// Read lock, **recovering** from any poisoning: a panic in another
    /// handler must not bring the whole server into a DoS.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Same for writing.
    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

// ─── SQLite persistence (write-through; the in-memory cache backs reads) ───

#[derive(Clone)]
struct Db {
    conn: Arc<Mutex<Connection>>,
}

enum PreparedVaultOperation {
    Put {
        id: String,
        blob: EncryptedBlob,
        blob_json: String,
    },
    Delete {
        id: String,
    },
}

enum DbVaultMutation {
    Applied,
    Stale,
}

enum IdentityPublication {
    Published(String),
    Conflict,
}

fn sqlite_artifact_path(path: &FsPath, suffix: &str) -> PathBuf {
    let mut artifact = path.as_os_str().to_os_string();
    artifact.push(suffix);
    PathBuf::from(artifact)
}

fn secure_database_parent(path: &FsPath) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| FsPath::new("."));
    let absolute_parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };
    for ancestor in absolute_parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "database parent chain must contain only real directories",
            ));
        }
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "database parent chain must not be writable by group or others",
                ));
            }
        }
    }
    Ok(())
}

fn secure_database_artifact(path: &FsPath, required: bool) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !required => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database artifact must be a regular file, not a symbolic link",
        ));
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "database artifact must not have hard links",
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        if fs::symlink_metadata(path)?.permissions().mode() & 0o777 != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database artifact permissions are not owner-only",
            ));
        }
    }
    Ok(())
}

fn prepare_database_path(path: &FsPath) -> io::Result<()> {
    secure_database_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => secure_database_artifact(path, true)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options.open(path)?;
            secure_database_artifact(path, true)?;
        }
        Err(error) => return Err(error),
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        secure_database_artifact(&sqlite_artifact_path(path, suffix), false)?;
    }
    Ok(())
}

fn secure_database_artifacts(path: &FsPath) -> io::Result<()> {
    secure_database_artifact(path, true)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        secure_database_artifact(&sqlite_artifact_path(path, suffix), false)?;
    }
    Ok(())
}

impl Db {
    fn open(path: &str) -> Self {
        let file_path = (path != ":memory:").then(|| FsPath::new(path));
        if let Some(file_path) = file_path {
            prepare_database_path(file_path).expect("secure database path");
        }
        let conn = if path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
        }
        .expect("open database");
        conn.execute_batch(
            // busy_timeout: with several processes sharing the DB (a supported
            // deployment — see create_account), cross-process lock contention
            // should wait a bounded moment instead of surfacing an instant
            // SQLITE_BUSY that handlers can only map to an opaque 500.
            // synchronous=NORMAL: the durable, fsync-light setting recommended
            // for WAL mode (FULL's extra fsyncs buy nothing under WAL).
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS accounts(
               email TEXT PRIMARY KEY, salt TEXT NOT NULL, kdf TEXT NOT NULL,
               wrapped_vault_key TEXT NOT NULL, auth_hash TEXT NOT NULL,
               vault_revision INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS items(
               email TEXT NOT NULL, id TEXT NOT NULL, blob TEXT NOT NULL,
               PRIMARY KEY(email, id));
             CREATE TABLE IF NOT EXISTS manifests(
               email TEXT PRIMARY KEY, blob TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS send_directory(
               email TEXT PRIMARY KEY, bastion_id TEXT UNIQUE NOT NULL,
               public TEXT NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS send_inbox(
               recipient_id TEXT NOT NULL, message_id TEXT NOT NULL,
               blob TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER,
               PRIMARY KEY(recipient_id, message_id));
             CREATE INDEX IF NOT EXISTS idx_inbox_recipient ON send_inbox(recipient_id);",
        )
        .expect("init schema");
        let has_vault_revision = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(accounts)")
                .expect("read schema");
            stmt.query_map([], |row| row.get::<_, String>(1))
                .expect("read account columns")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("read account columns")
                .iter()
                .any(|column| column == "vault_revision")
        };
        if !has_vault_revision {
            conn.execute(
                "ALTER TABLE accounts ADD COLUMN vault_revision INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .expect("migrate vault revision");
        }
        if let Some(file_path) = file_path {
            secure_database_artifacts(file_path).expect("secure database artifacts");
        }
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Inserts a new account without ever replacing an existing credential.
    /// Returns `false` when another request or process already claimed `email`.
    fn create_account(
        &self,
        email: &str,
        salt: &str,
        kdf_json: &str,
        wrapped_json: &str,
        auth_hash: &str,
    ) -> rusqlite::Result<bool> {
        let inserted = self.lock().execute(
            "INSERT INTO accounts(email,salt,kdf,wrapped_vault_key,auth_hash) \
             VALUES(?1,?2,?3,?4,?5) ON CONFLICT(email) DO NOTHING",
            params![email, salt, kdf_json, wrapped_json, auth_hash],
        )?;
        Ok(inserted == 1)
    }

    fn commit_vault_mutation(
        &self,
        email: &str,
        expected_revision: u64,
        next_revision: u64,
        operations: &[PreparedVaultOperation],
        manifest_json: Option<&str>,
    ) -> rusqlite::Result<DbVaultMutation> {
        let expected_revision = persisted_revision(expected_revision)?;
        let next_revision = persisted_revision(next_revision)?;
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let updated = tx.execute(
            "UPDATE accounts SET vault_revision=?1 WHERE email=?2 AND vault_revision=?3",
            params![next_revision, email, expected_revision],
        )?;
        if updated != 1 {
            return Ok(DbVaultMutation::Stale);
        }
        for operation in operations {
            match operation {
                PreparedVaultOperation::Put { id, blob_json, .. } => {
                    tx.execute(
                        "INSERT OR REPLACE INTO items(email,id,blob) VALUES(?1,?2,?3)",
                        params![email, id, blob_json],
                    )?;
                }
                PreparedVaultOperation::Delete { id } => {
                    tx.execute(
                        "DELETE FROM items WHERE email=?1 AND id=?2",
                        params![email, id],
                    )?;
                }
            }
        }
        if let Some(manifest_json) = manifest_json {
            tx.execute(
                "INSERT OR REPLACE INTO manifests(email,blob) VALUES(?1,?2)",
                params![email, manifest_json],
            )?;
        }
        tx.commit()?;
        Ok(DbVaultMutation::Applied)
    }

    /// Loads all accounts (with their items and manifest) at startup.
    fn load_accounts(
        &self,
    ) -> Result<HashMap<String, AccountRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let conn = self.lock();
        let mut accounts: HashMap<String, AccountRecord> = HashMap::new();

        {
            let mut stmt = conn.prepare(
                "SELECT email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision FROM accounts",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?;
            for row in rows {
                let (email, salt, kdf_s, wrapped_s, auth_hash, vault_revision) = row?;
                let kdf: KdfParams = serde_json::from_str(&kdf_s)?;
                let wrapped_vault_key: EncryptedBlob = serde_json::from_str(&wrapped_s)?;
                validate_persisted_credentials(&email, &salt, kdf, &wrapped_vault_key, &auth_hash)?;
                let vault_revision = u64::try_from(vault_revision).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "negative vault revision")
                })?;
                accounts.insert(
                    email,
                    AccountRecord {
                        salt,
                        kdf,
                        wrapped_vault_key,
                        auth_hash,
                        items: HashMap::new(),
                        item_bytes: HashMap::new(),
                        manifest: None,
                        manifest_bytes: 0,
                        stored_bytes: 0,
                        vault_revision,
                    },
                );
            }
        }
        {
            let mut stmt = conn.prepare("SELECT email,id,blob FROM items")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (email, id, blob_s) = row?;
                let blob = serde_json::from_str(&blob_s)?;
                let acc = accounts.get_mut(&email).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("orphaned item {id:?} for account {email:?}"),
                    )
                })?;
                if !is_valid_item_id(&id)
                    || blob_s.len() > MAX_VAULT_BLOB_BYTES
                    || acc.items.len() >= MAX_VAULT_ITEMS
                    || acc
                        .stored_bytes
                        .checked_add(blob_s.len())
                        .is_none_or(|total| total > MAX_VAULT_BYTES)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("vault quota exceeded for account {email:?}"),
                    )
                    .into());
                }
                acc.stored_bytes += blob_s.len();
                acc.item_bytes.insert(id.clone(), blob_s.len());
                acc.items.insert(id, blob);
            }
        }
        {
            let mut stmt = conn.prepare("SELECT email,blob FROM manifests")?;
            let rows =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            for row in rows {
                let (email, blob_s) = row?;
                let blob = serde_json::from_str(&blob_s)?;
                let acc = accounts.get_mut(&email).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("orphaned manifest for account {email:?}"),
                    )
                })?;
                if blob_s.len() > MAX_VAULT_MANIFEST_BYTES
                    || acc
                        .stored_bytes
                        .checked_add(blob_s.len())
                        .is_none_or(|total| total > MAX_VAULT_BYTES)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("vault quota exceeded for account {email:?}"),
                    )
                    .into());
                }
                acc.stored_bytes += blob_s.len();
                acc.manifest_bytes = blob_s.len();
                acc.manifest = Some(blob);
            }
        }
        Ok(accounts)
    }
}

fn persisted_revision(revision: u64) -> rusqlite::Result<i64> {
    i64::try_from(revision).map_err(|_| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault revision exceeds SQLite integer range",
        )))
    })
}

// ─── HTTP errors (deliberately terse messages) ───

struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

// ─── DTO ───

#[derive(Deserialize)]
struct CreateAccount {
    email: String,
    registration: Registration,
}

#[derive(Serialize)]
struct Prelogin {
    salt: String,
    kdf: KdfParams,
    wrapped_vault_key: EncryptedBlob,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    /// Base64 authentication secret derived on the client side.
    auth_secret: AuthSecret,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct VaultResponse {
    items: HashMap<String, EncryptedBlob>,
    manifest: Option<EncryptedBlob>,
    revision: u64,
}

#[derive(Deserialize)]
struct BlobBody {
    blob: EncryptedBlob,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultTransactionRequest {
    expected_revision: u64,
    operations: Vec<VaultOperation>,
    manifest: EncryptedBlob,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum VaultOperation {
    Put { id: String, blob: EncryptedBlob },
    Delete { id: String },
}

#[derive(Serialize)]
struct VaultTransactionResponse {
    revision: u64,
}

#[derive(Clone)]
struct AuthenticatedAccount(String);

// ─── Handlers ───

async fn health() -> &'static str {
    "ok"
}

async fn create_account(
    State(st): State<AppState>,
    Json(req): Json<CreateAccount>,
) -> Result<StatusCode, ApiError> {
    validate_account_id(&req.email)?;
    validate_registration(&req.registration)?;
    auth_rate_limit(
        &st,
        "global",
        "account-create-global",
        st.auth_rate_limits.account_creations_global,
    )?;
    auth_rate_limit(
        &st,
        &req.email,
        "account-create-account",
        st.auth_rate_limits.account_creations_per_account,
    )?;
    // Reject a known duplicate before paying the Argon2 cost. The authoritative
    // collision check is repeated under the write lock after hashing.
    if st.read().accounts.contains_key(&req.email) {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    // Slow hash on a dedicated blocking thread (no starvation of the async runtime).
    let secret = req.registration.auth_secret;
    let permit = auth_permit(&st)?;
    let auth_hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_secret(secret.expose_b64())
    })
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "join error"))?
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "hash failure"))?;

    let kdf_json = serde_json::to_string(&req.registration.kdf)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    let wrapped_json = serde_json::to_string(&req.registration.wrapped_vault_key)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    // Serialize the authoritative insert and cache update. SQLite's conflict
    // clause also protects deployments with multiple processes sharing the DB.
    let mut inner = st.write();
    if inner.accounts.contains_key(&req.email) {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    let created = st
        .db
        .create_account(
            &req.email,
            &req.registration.salt,
            &kdf_json,
            &wrapped_json,
            &auth_hash,
        )
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    if !created {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    inner.accounts.insert(
        req.email,
        AccountRecord {
            salt: req.registration.salt,
            kdf: req.registration.kdf,
            wrapped_vault_key: req.registration.wrapped_vault_key,
            auth_hash,
            items: HashMap::new(),
            item_bytes: HashMap::new(),
            manifest: None,
            manifest_bytes: 0,
            stored_bytes: 0,
            vault_revision: 0,
        },
    );
    Ok(StatusCode::CREATED)
}

async fn prelogin(
    State(st): State<AppState>,
    Path(email): Path<String>,
) -> Result<Json<Prelogin>, ApiError> {
    validate_account_id(&email)?;
    // Unauthenticated existence oracle: throttle before the account lookup so
    // bulk enumeration (and KDF-parameter harvesting) is rate-bound.
    auth_rate_limit(
        &st,
        "global",
        "prelogin-global",
        st.auth_rate_limits.prelogins_global,
    )?;
    auth_rate_limit(
        &st,
        &email,
        "prelogin-account",
        st.auth_rate_limits.prelogins_per_account,
    )?;
    let inner = st.read();
    let acc = inner
        .accounts
        .get(&email)
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no such account"))?;
    Ok(Json(Prelogin {
        salt: acc.salt.clone(),
        kdf: acc.kdf,
        wrapped_vault_key: acc.wrapped_vault_key.clone(),
    }))
}

async fn create_session(
    State(st): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    validate_account_id(&req.email)?;
    if !is_exact_b64(req.auth_secret.expose_b64(), AUTH_SECRET_BYTES) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    auth_rate_limit(
        &st,
        "global",
        "login-global",
        st.auth_rate_limits.login_attempts_global,
    )?;
    auth_rate_limit(
        &st,
        &req.email,
        "login-account",
        st.auth_rate_limits.login_attempts_per_account,
    )?;
    // We copy the hash, then release the lock before the slow verification.
    let phc = st
        .read()
        .accounts
        .get(&req.email)
        .map(|a| a.auth_hash.clone());
    // Same response for "unknown account" and "wrong secret" — and the same
    // Argon2id cost: unknown accounts verify against a process-constant dummy
    // hash so response timing cannot separate the two cases.
    let known = phc.is_some();
    let phc = phc.unwrap_or_else(|| DUMMY_PHC.clone());
    let secret = req.auth_secret;
    let permit = auth_permit(&st)?;
    let ok = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_secret(secret.expose_b64(), &phc)
    })
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "join error"))?;
    if !ok || !known {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let now = Instant::now();
    let expires_at = now + st.token_ttl;
    let mut inner = st.write();
    inner.sessions.retain(|_, session| now < session.expires_at);
    let oldest = inner
        .sessions
        .iter()
        .filter(|(_, session)| session.email == req.email)
        .min_by_key(|(_, session)| session.created_at)
        .map(|(token, _)| token.clone());
    let account_sessions = inner
        .sessions
        .values()
        .filter(|session| session.email == req.email)
        .count();
    if account_sessions >= MAX_SESSIONS_PER_ACCOUNT {
        if let Some(token) = oldest {
            inner.sessions.remove(&token);
        }
    }
    if inner.sessions.len() >= MAX_ACTIVE_SESSIONS {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "session capacity reached",
        ));
    }
    let mut token = new_token();
    while inner.sessions.contains_key(&token) {
        token = new_token();
    }
    inner.sessions.insert(
        token.clone(),
        Session {
            email: req.email,
            created_at: now,
            expires_at,
        },
    );
    Ok(Json(LoginResponse { token }))
}

/// Authenticate before Axum extracts the larger transaction body. This keeps
/// the expanded route-specific limit unavailable to unauthenticated callers.
async fn authenticate_vault_transaction(
    State(st): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let email = require_auth(&st, request.headers())?;
    request.extensions_mut().insert(AuthenticatedAccount(email));
    Ok(next.run(request).await)
}

async fn get_vault(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultResponse>, ApiError> {
    let email = require_auth(&st, &headers)?;
    rate_limit(&st, &email, "vault-read", MAX_VAULT_READS_PER_MIN)?;
    let inner = st.read();
    let acc = inner
        .accounts
        .get(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    Ok(Json(VaultResponse {
        items: acc.items.clone(),
        manifest: acc.manifest.clone(),
        revision: acc.vault_revision,
    }))
}

async fn apply_vault_transaction(
    State(st): State<AppState>,
    Extension(AuthenticatedAccount(email)): Extension<AuthenticatedAccount>,
    Json(body): Json<VaultTransactionRequest>,
) -> Result<Json<VaultTransactionResponse>, ApiError> {
    if body.operations.len() > MAX_VAULT_TRANSACTION_OPS {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too many vault operations",
        ));
    }
    let manifest_json = serde_json::to_string(&body.manifest)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    if manifest_json.len() > MAX_VAULT_MANIFEST_BYTES {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "manifest too large",
        ));
    }

    let mut ids = HashSet::with_capacity(body.operations.len());
    let mut operations = Vec::with_capacity(body.operations.len());
    for operation in body.operations {
        let prepared = match operation {
            VaultOperation::Put { id, blob } => {
                validate_item_id(&id)?;
                if !ids.insert(id.clone()) {
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        "duplicate item operation",
                    ));
                }
                let blob_json = serde_json::to_string(&blob)
                    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
                if blob_json.len() > MAX_VAULT_BLOB_BYTES {
                    return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "item too large"));
                }
                PreparedVaultOperation::Put {
                    id,
                    blob,
                    blob_json,
                }
            }
            VaultOperation::Delete { id } => {
                validate_item_id(&id)?;
                if !ids.insert(id.clone()) {
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        "duplicate item operation",
                    ));
                }
                PreparedVaultOperation::Delete { id }
            }
        };
        operations.push(prepared);
    }

    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    if body.expected_revision != acc.vault_revision {
        return Err(ApiError(StatusCode::CONFLICT, "stale vault revision"));
    }
    let next_revision = next_vault_revision(acc.vault_revision)?;
    let (next_item_count, next_stored_bytes) =
        projected_vault_usage(acc, &operations, manifest_json.len())?;
    if next_item_count > MAX_VAULT_ITEMS {
        return Err(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault item quota exceeded",
        ));
    }
    if next_stored_bytes > MAX_VAULT_BYTES {
        return Err(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault storage quota exceeded",
        ));
    }

    persist_vault_mutation(
        &st,
        &email,
        acc.vault_revision,
        next_revision,
        &operations,
        Some(&manifest_json),
    )?;

    for operation in operations {
        match operation {
            PreparedVaultOperation::Put {
                id,
                blob,
                blob_json,
            } => {
                acc.item_bytes.insert(id.clone(), blob_json.len());
                acc.items.insert(id, blob);
            }
            PreparedVaultOperation::Delete { id } => {
                acc.item_bytes.remove(&id);
                acc.items.remove(&id);
            }
        }
    }
    acc.manifest = Some(body.manifest);
    acc.manifest_bytes = manifest_json.len();
    acc.stored_bytes = next_stored_bytes;
    acc.vault_revision = next_revision;

    Ok(Json(VaultTransactionResponse {
        revision: next_revision,
    }))
}

async fn put_item(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<BlobBody>,
) -> Result<(StatusCode, [(&'static str, &'static str); 1]), ApiError> {
    validate_item_id(&id)?;
    let email = require_auth(&st, &headers)?;
    let blob_json = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    if blob_json.len() > MAX_VAULT_BLOB_BYTES {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "item too large"));
    }
    // Keep persistence and the read cache in one ordered critical section. If
    // concurrent requests write the same id, the cache winner must be the same
    // request as the SQLite winner.
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let is_new = !acc.items.contains_key(&id);
    if is_new && acc.items.len() >= MAX_VAULT_ITEMS {
        return Err(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault item quota exceeded",
        ));
    }
    let previous_bytes = acc.item_bytes.get(&id).copied().unwrap_or(0);
    let next_bytes = acc
        .stored_bytes
        .checked_sub(previous_bytes)
        .and_then(|total| total.checked_add(blob_json.len()))
        .filter(|total| *total <= MAX_VAULT_BYTES)
        .ok_or(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault storage quota exceeded",
        ))?;
    let next_revision = next_vault_revision(acc.vault_revision)?;
    let operations = [PreparedVaultOperation::Put {
        id: id.clone(),
        blob: body.blob.clone(),
        blob_json: blob_json.clone(),
    }];
    persist_vault_mutation(
        &st,
        &email,
        acc.vault_revision,
        next_revision,
        &operations,
        None,
    )?;
    acc.stored_bytes = next_bytes;
    acc.item_bytes.insert(id.clone(), blob_json.len());
    acc.items.insert(id, body.blob);
    acc.vault_revision = next_revision;
    Ok(deprecated_vault_mutation_response())
}

async fn delete_item(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(StatusCode, [(&'static str, &'static str); 1]), ApiError> {
    validate_item_id(&id)?;
    let email = require_auth(&st, &headers)?;
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let next_revision = next_vault_revision(acc.vault_revision)?;
    let operations = [PreparedVaultOperation::Delete { id: id.clone() }];
    persist_vault_mutation(
        &st,
        &email,
        acc.vault_revision,
        next_revision,
        &operations,
        None,
    )?;
    if let Some(bytes) = acc.item_bytes.remove(&id) {
        acc.stored_bytes = acc.stored_bytes.saturating_sub(bytes);
    }
    acc.items.remove(&id);
    acc.vault_revision = next_revision;
    Ok(deprecated_vault_mutation_response())
}

async fn put_manifest(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BlobBody>,
) -> Result<(StatusCode, [(&'static str, &'static str); 1]), ApiError> {
    let email = require_auth(&st, &headers)?;
    let blob_json = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    if blob_json.len() > MAX_VAULT_MANIFEST_BYTES {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "manifest too large",
        ));
    }
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let next_bytes = acc
        .stored_bytes
        .checked_sub(acc.manifest_bytes)
        .and_then(|total| total.checked_add(blob_json.len()))
        .filter(|total| *total <= MAX_VAULT_BYTES)
        .ok_or(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault storage quota exceeded",
        ))?;
    let next_revision = next_vault_revision(acc.vault_revision)?;
    persist_vault_mutation(
        &st,
        &email,
        acc.vault_revision,
        next_revision,
        &[],
        Some(&blob_json),
    )?;
    acc.stored_bytes = next_bytes;
    acc.manifest_bytes = blob_json.len();
    acc.manifest = Some(body.blob);
    acc.vault_revision = next_revision;
    Ok(deprecated_vault_mutation_response())
}

// ─── Helpers ───

fn deprecated_vault_mutation_response() -> (StatusCode, [(&'static str, &'static str); 1]) {
    (StatusCode::NO_CONTENT, [("deprecation", "true")])
}

fn next_vault_revision(current: u64) -> Result<u64, ApiError> {
    current
        .checked_add(1)
        .filter(|revision| i64::try_from(*revision).is_ok())
        .ok_or(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault revision exhausted",
        ))
}

fn projected_vault_usage(
    acc: &AccountRecord,
    operations: &[PreparedVaultOperation],
    manifest_bytes: usize,
) -> Result<(usize, usize), ApiError> {
    let mut item_count = acc.items.len();
    let mut stored_bytes = acc
        .stored_bytes
        .checked_sub(acc.manifest_bytes)
        .and_then(|total| total.checked_add(manifest_bytes))
        .ok_or(ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault storage quota exceeded",
        ))?;
    for operation in operations {
        match operation {
            PreparedVaultOperation::Put { id, blob_json, .. } => {
                if !acc.items.contains_key(id) {
                    item_count = item_count.checked_add(1).ok_or(ApiError(
                        StatusCode::INSUFFICIENT_STORAGE,
                        "vault item quota exceeded",
                    ))?;
                }
                let previous_bytes = acc.item_bytes.get(id).copied().unwrap_or(0);
                stored_bytes = stored_bytes
                    .checked_sub(previous_bytes)
                    .and_then(|total| total.checked_add(blob_json.len()))
                    .ok_or(ApiError(
                        StatusCode::INSUFFICIENT_STORAGE,
                        "vault storage quota exceeded",
                    ))?;
            }
            PreparedVaultOperation::Delete { id } => {
                if let Some(previous_bytes) = acc.item_bytes.get(id) {
                    item_count = item_count.checked_sub(1).ok_or(ApiError(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "vault accounting error",
                    ))?;
                    stored_bytes = stored_bytes.checked_sub(*previous_bytes).ok_or(ApiError(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "vault accounting error",
                    ))?;
                }
            }
        }
    }
    Ok((item_count, stored_bytes))
}

fn persist_vault_mutation(
    st: &AppState,
    email: &str,
    expected_revision: u64,
    next_revision: u64,
    operations: &[PreparedVaultOperation],
    manifest_json: Option<&str>,
) -> Result<(), ApiError> {
    match st
        .db
        .commit_vault_mutation(
            email,
            expected_revision,
            next_revision,
            operations,
            manifest_json,
        )
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        DbVaultMutation::Applied => Ok(()),
        // The in-memory cache is process-local. A DB-only conflict means
        // another process changed the same account and this process must not
        // pretend its cache can satisfy a client retry.
        DbVaultMutation::Stale => Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault cache out of sync",
        )),
    }
}

fn validate_account_id(email: &str) -> Result<(), ApiError> {
    let valid_shape = email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && !domain.is_empty() && !domain.contains('@')
    });
    if email.is_empty()
        || email.len() > MAX_ACCOUNT_ID_BYTES
        || !email.is_ascii()
        || email.trim() != email
        || email
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || !valid_shape
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid account id"));
    }
    Ok(())
}

fn auth_permit(st: &AppState) -> Result<OwnedSemaphorePermit, ApiError> {
    st.auth_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "authentication busy"))
}

fn validate_item_id(id: &str) -> Result<(), ApiError> {
    if !is_valid_item_id(id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid item id"));
    }
    Ok(())
}

fn is_valid_item_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ITEM_ID_BYTES
        && id.is_ascii()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\' | b'?' | b'#'))
}

fn is_exact_b64(value: &str, decoded_len: usize) -> bool {
    if value.len()
        > decoded_len
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(8)
    {
        return false;
    }
    B64.decode(value)
        .is_ok_and(|bytes| bytes.len() == decoded_len && B64.encode(bytes) == value)
}

fn parse_valid_auth_hash(phc: &str) -> Option<PasswordHash<'_>> {
    let parsed = PasswordHash::new(phc).ok()?;
    if parsed.algorithm.as_str() != "argon2id"
        || parsed.version != Some(0x13)
        || parsed.to_string() != phc
    {
        return None;
    }
    let params = ArgonParams::try_from(&parsed).ok()?;
    if params.m_cost() != ArgonParams::DEFAULT_M_COST
        || params.t_cost() != ArgonParams::DEFAULT_T_COST
        || params.p_cost() != ArgonParams::DEFAULT_P_COST
        || !params.keyid().is_empty()
        || !params.data().is_empty()
        || params.output_len() != Some(AUTH_HASH_OUTPUT_BYTES)
    {
        return None;
    }
    let salt = parsed.salt?;
    let mut salt_bytes = [0u8; 64];
    if salt.decode_b64(&mut salt_bytes).ok()?.len() != AUTH_HASH_SALT_BYTES
        || parsed.hash?.len() != AUTH_HASH_OUTPUT_BYTES
    {
        return None;
    }
    Some(parsed)
}

fn validate_persisted_credentials(
    email: &str,
    salt: &str,
    kdf: KdfParams,
    wrapped: &EncryptedBlob,
    auth_hash: &str,
) -> Result<(), io::Error> {
    // Unlock accepts legacy KDFs below today's creation floor, but persisted
    // values must still be structurally valid and remain inside the anti-DoS
    // ceiling.
    let kdf_is_valid = kdf.validate_for_unlock().is_ok()
        && ArgonParams::new(
            kdf.mem_kib,
            kdf.iterations,
            kdf.parallelism,
            Some(AUTH_HASH_OUTPUT_BYTES),
        )
        .is_ok();
    let valid = validate_account_id(email).is_ok()
        && is_exact_b64(salt, REGISTRATION_SALT_BYTES)
        && kdf_is_valid
        && wrapped.v == crypto_core::aead::FORMAT_VERSION
        && is_exact_b64(&wrapped.nonce, WRAPPED_KEY_NONCE_BYTES)
        && is_exact_b64(&wrapped.ct, WRAPPED_KEY_CIPHERTEXT_BYTES)
        && parse_valid_auth_hash(auth_hash).is_some();
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid persisted credentials for account {email:?}"),
        ));
    }
    Ok(())
}

fn validate_registration(registration: &Registration) -> Result<(), ApiError> {
    let wrapped = &registration.wrapped_vault_key;
    let valid = registration.version == crypto_core::aead::FORMAT_VERSION
        && registration.kdf.validate_for_new_vault().is_ok()
        && is_exact_b64(&registration.salt, REGISTRATION_SALT_BYTES)
        && is_exact_b64(registration.auth_secret.expose_b64(), AUTH_SECRET_BYTES)
        && wrapped.v == crypto_core::aead::FORMAT_VERSION
        && is_exact_b64(&wrapped.nonce, WRAPPED_KEY_NONCE_BYTES)
        && is_exact_b64(&wrapped.ct, WRAPPED_KEY_CIPHERTEXT_BYTES);
    if !valid {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid registration data",
        ));
    }
    Ok(())
}

/// Revokes the current session (logout).
async fn delete_session(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let token = bearer_token(&headers)?.to_string();
    st.write().sessions.remove(&token);
    Ok(StatusCode::NO_CONTENT)
}

/// Extracts the "Authorization: Bearer …" token.
fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))
}

/// Validates the token (existence + non-expiration) and returns the email.
/// Evicts an expired token along the way.
fn require_auth(st: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = bearer_token(headers)?.to_string();
    let mut inner = st.write();
    let email = match inner.sessions.get(&token) {
        Some(s) if Instant::now() < s.expires_at => Some(s.email.clone()),
        Some(_) => None, // expired
        None => return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token")),
    };
    match email {
        Some(email) => Ok(email),
        None => {
            inner.sessions.remove(&token);
            Err(ApiError(StatusCode::UNAUTHORIZED, "session expired"))
        }
    }
}

/// Process-constant dummy PHC hash of a random secret nobody knows.
///
/// Logins for unknown accounts verify against this hash so they pay the same
/// Argon2id cost as a wrong password for a real account. Without it, response
/// time separated "no such account" (~µs) from "wrong secret" (~100 ms),
/// re-opening the account-enumeration oracle the identical 401 body closes.
static DUMMY_PHC: LazyLock<String> = LazyLock::new(|| {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    hash_secret(&data_encoding::BASE64.encode(&secret)).expect("hash dummy login secret")
});

/// Slow Argon2id hash (PHC) of the authentication secret.
fn hash_secret(secret: &str) -> Result<String, ()> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ())?;
    if parse_valid_auth_hash(&phc).is_none() {
        return Err(());
    }
    Ok(phc)
}

/// Verifies a secret against a PHC hash, in constant time (via `argon2`).
fn verify_secret(secret: &str, phc: &str) -> bool {
    match parse_valid_auth_hash(phc) {
        Some(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        None => false,
    }
}

/// Random 256-bit session token, hex-encoded.
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    data_encoding::HEXLOWER.encode(&bytes)
}

// ════════════════════════════════════════════════════════════════════════════
//  Bastion Send — directory + inbox (server stores only opaque blobs + public
//  keys; see docs/bastion-send-design.md §4/§8). The server never sees plaintext
//  or any private key. recipient_id / message_id are routing metadata only.
// ════════════════════════════════════════════════════════════════════════════

/// New 128-bit opaque Bastion ID (base32, non-enumerable).
fn new_bastion_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

/// Fixed-window per-key rate limit. New keys are rejected when the strictly
/// bounded state map is full and no expired window can be reclaimed.
fn rate_limit_map(
    rate: &mut HashMap<String, RateState>,
    max_entries: usize,
    window: Duration,
    subject: &str,
    bucket: &str,
    max: u32,
) -> Result<(), ApiError> {
    if max == 0 {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let key = format!("{bucket}\0{subject}");
    let now = Instant::now();

    if let Some(entry) = rate.get_mut(&key) {
        if now.saturating_duration_since(entry.window_start) >= window {
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= max {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
        }
        entry.count += 1;
        return Ok(());
    }

    if rate.len() >= max_entries {
        rate.retain(|_, entry| now.saturating_duration_since(entry.window_start) < window);
    }

    if rate.len() >= max_entries {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "rate limiter capacity reached",
        ));
    }

    rate.insert(
        key,
        RateState {
            window_start: now,
            count: 1,
        },
    );
    Ok(())
}

/// Send abuse limits are kept separate from unauthenticated auth limits so an
/// attacker cannot consume one subsystem's counter capacity through the other.
fn rate_limit(st: &AppState, subject: &str, bucket: &str, max: u32) -> Result<(), ApiError> {
    let mut inner = st.write();
    rate_limit_map(
        &mut inner.rate,
        st.max_rate_entries,
        st.rate_window,
        subject,
        bucket,
        max,
    )
}

fn auth_rate_limit(st: &AppState, subject: &str, bucket: &str, max: u32) -> Result<(), ApiError> {
    let mut inner = st.write();
    rate_limit_map(
        &mut inner.auth_rate,
        st.auth_rate_limits.max_entries,
        st.auth_rate_limits.window,
        subject,
        bucket,
        max,
    )
}

impl Db {
    fn classify_existing_identity(
        bastion_id: String,
        stored_public: &str,
        requested_public: &PublicIdentity,
    ) -> rusqlite::Result<IdentityPublication> {
        let stored = serde_json::from_str::<PublicIdentity>(stored_public)
            .map_err(|error| stored_data_error(1, rusqlite::types::Type::Text, error))?;
        stored
            .validate()
            .map_err(|error| stored_data_error(1, rusqlite::types::Type::Text, error))?;
        Ok(if stored == *requested_public {
            IdentityPublication::Published(bastion_id)
        } else {
            IdentityPublication::Conflict
        })
    }

    /// Publish once. Identical retries are idempotent; changing either key or
    /// the version requires a future proof-authorized rotation protocol.
    fn publish_identity(
        &self,
        email: &str,
        public: &PublicIdentity,
        public_json: &str,
    ) -> rusqlite::Result<IdentityPublication> {
        let conn = self.lock();
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT bastion_id, public FROM send_directory WHERE email=?1",
                [email],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((bastion_id, stored_public)) = existing {
            return Self::classify_existing_identity(bastion_id, &stored_public, public);
        }
        // New account: retry generation on the (astronomically rare) id collision.
        for _ in 0..8 {
            let id = new_bastion_id();
            match conn.execute(
                "INSERT INTO send_directory(email, bastion_id, public, created_at) VALUES(?1,?2,?3,?4)",
                params![email, id, public_json, now_secs()],
            ) {
                Ok(_) => return Ok(IdentityPublication::Published(id)),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    // Another server process may have published this account
                    // after our initial read. Resolve that race as either an
                    // idempotent success or an immutable-identity conflict.
                    let existing: Option<(String, String)> = conn
                        .query_row(
                            "SELECT bastion_id, public FROM send_directory WHERE email=?1",
                            [email],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if let Some((bastion_id, stored_public)) = existing {
                        return Self::classify_existing_identity(
                            bastion_id,
                            &stored_public,
                            public,
                        );
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        // 8 consecutive 128-bit collisions is statistically impossible; surface
        // a generic error (the handler maps it to 500).
        Err(rusqlite::Error::QueryReturnedNoRows)
    }

    fn whoami(&self, email: &str) -> rusqlite::Result<Option<(String, String)>> {
        self.lock()
            .query_row(
                "SELECT bastion_id, public FROM send_directory WHERE email=?1",
                [email],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
    }

    fn directory_lookup(&self, bastion_id: &str) -> rusqlite::Result<Option<String>> {
        self.lock()
            .query_row(
                "SELECT public FROM send_directory WHERE bastion_id=?1",
                [bastion_id],
                |r| r.get(0),
            )
            .optional()
    }

    fn bastion_id_for(&self, email: &str) -> rusqlite::Result<Option<String>> {
        self.lock()
            .query_row(
                "SELECT bastion_id FROM send_directory WHERE email=?1",
                [email],
                |r| r.get(0),
            )
            .optional()
    }

    /// Atomically enforce the quota and insert (one lock hold → no count/insert
    /// TOCTOU). Dedupe is per-recipient (PK is `(recipient_id, message_id)`).
    fn insert_inbox(
        &self,
        message_id: &str,
        recipient_id: &str,
        blob: &str,
        expires_at: Option<i64>,
        max: i64,
    ) -> rusqlite::Result<InboxInsert> {
        let conn = self.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM send_inbox WHERE recipient_id=?1",
            [recipient_id],
            |r| r.get(0),
        )?;
        if count >= max {
            return Ok(InboxInsert::Full);
        }
        let n = conn.execute(
            "INSERT OR IGNORE INTO send_inbox(message_id, recipient_id, blob, created_at, expires_at)
             VALUES(?1,?2,?3,?4,?5)",
            params![message_id, recipient_id, blob, now_secs(), expires_at],
        )?;
        Ok(if n > 0 {
            InboxInsert::Inserted
        } else {
            InboxInsert::Duplicate
        })
    }

    fn purge_expired(&self, recipient_id: &str, now: i64) -> rusqlite::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "SELECT created_at, expires_at FROM send_inbox
                 WHERE recipient_id=?1 AND expires_at IS NOT NULL AND expires_at < ?2",
            )?;
            let rows = stmt.query_map(params![recipient_id, now], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (created_at, expires_at) = row?;
                if created_at <= 0
                    || expires_at <= created_at
                    || expires_at > created_at.saturating_add(MAX_SEND_TTL_SECS)
                {
                    return Err(stored_data_error(
                        1,
                        rusqlite::types::Type::Integer,
                        io::Error::new(io::ErrorKind::InvalidData, "invalid stored expiration"),
                    ));
                }
            }
        }
        tx.execute(
            "DELETE FROM send_inbox
             WHERE recipient_id=?1 AND expires_at IS NOT NULL AND expires_at < ?2",
            params![recipient_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn inbox_list(&self, recipient_id: &str, now: i64) -> rusqlite::Result<Vec<InboxItem>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT message_id, blob, created_at, expires_at FROM send_inbox
             WHERE recipient_id=?1 AND (expires_at IS NULL OR expires_at >= ?2)
             ORDER BY created_at ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![recipient_id, now, MAX_INBOX_PAGE], |r| {
            let message_id: String = r.get(0)?;
            let blob_json: String = r.get(1)?;
            let created_at: i64 = r.get(2)?;
            let expires_at: Option<i64> = r.get(3)?;
            let blob: SendBlob = serde_json::from_str(&blob_json)
                .map_err(|e| stored_data_error(1, rusqlite::types::Type::Text, e))?;
            if !valid_message_id(&message_id) {
                return Err(stored_data_error(
                    0,
                    rusqlite::types::Type::Text,
                    io::Error::new(io::ErrorKind::InvalidData, "invalid stored message id"),
                ));
            }
            blob.validate_stored_routing(&message_id, recipient_id)
                .map_err(|e| stored_data_error(1, rusqlite::types::Type::Text, e))?;
            if created_at <= 0 {
                return Err(stored_data_error(
                    2,
                    rusqlite::types::Type::Integer,
                    io::Error::new(io::ErrorKind::InvalidData, "invalid stored creation time"),
                ));
            }
            if expires_at.is_some_and(|expires_at| {
                expires_at <= created_at
                    || expires_at > created_at.saturating_add(MAX_SEND_TTL_SECS)
            }) {
                return Err(stored_data_error(
                    3,
                    rusqlite::types::Type::Integer,
                    io::Error::new(io::ErrorKind::InvalidData, "invalid stored expiration"),
                ));
            }
            Ok(InboxItem {
                message_id,
                blob,
                created_at,
                expires_at,
            })
        })?;
        // Propagate DB row errors instead of silently dropping them.
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Delete a message only if it belongs to `recipient_id` (read-once).
    fn inbox_delete(&self, message_id: &str, recipient_id: &str) -> rusqlite::Result<usize> {
        self.lock().execute(
            "DELETE FROM send_inbox WHERE message_id=?1 AND recipient_id=?2",
            params![message_id, recipient_id],
        )
    }
}

#[derive(Serialize)]
struct WhoAmI {
    bastion_id: String,
    public: PublicIdentity,
}

#[derive(Serialize)]
struct PublishResponse {
    bastion_id: String,
}

#[derive(Deserialize)]
struct SendPost {
    recipient_id: String,
    message_id: String,
    blob: SendBlob,
    expires_at: Option<i64>,
}

#[derive(Serialize)]
struct InboxItem {
    message_id: String,
    blob: SendBlob,
    created_at: i64,
    expires_at: Option<i64>,
}

/// Outcome of an atomic inbox insert (quota + dedupe checked under one lock).
enum InboxInsert {
    Inserted,
    Duplicate,
    Full,
}

/// Publish the caller's validated Send public identity. Identical retries are
/// idempotent; key changes require a separate proof-authorized protocol.
async fn publish_identity(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(public): Json<PublicIdentity>,
) -> Result<Json<PublishResponse>, ApiError> {
    let email = require_auth(&st, &headers)?;
    public
        .validate()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid public identity"))?;
    let public_json = serde_json::to_string(&public)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "bad json"))?;
    if public_json.len() > MAX_SEND_BLOB {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "identity too large",
        ));
    }
    let publication = st
        .db
        .publish_identity(&email, &public, &public_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    match publication {
        IdentityPublication::Published(bastion_id) => Ok(Json(PublishResponse { bastion_id })),
        IdentityPublication::Conflict => Err(ApiError(
            StatusCode::CONFLICT,
            "send identity already published; rotation proof required",
        )),
    }
}

/// The caller's own directory entry (so the app learns its Bastion ID).
async fn send_whoami(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WhoAmI>, ApiError> {
    let email = require_auth(&st, &headers)?;
    match st
        .db
        .whoami(&email)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        Some((bastion_id, public)) => {
            let public = serde_json::from_str::<PublicIdentity>(&public).map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "invalid stored identity")
            })?;
            public.validate().map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "invalid stored identity")
            })?;
            Ok(Json(WhoAmI { bastion_id, public }))
        }
        None => Err(ApiError(StatusCode::NOT_FOUND, "no identity published")),
    }
}

/// Resolve a Bastion ID to its public identity. Authenticated, exact-match,
/// rate-limited (no enumeration).
async fn send_directory(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(bastion_id): Path<String>,
) -> Result<Json<PublicIdentity>, ApiError> {
    let email = require_auth(&st, &headers)?;
    rate_limit(&st, &email, "lookup", MAX_LOOKUPS_PER_MIN)?;
    if !valid_bastion_id(&bastion_id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad bastion id"));
    }
    match st
        .db
        .directory_lookup(&bastion_id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        Some(public) => {
            let public = serde_json::from_str::<PublicIdentity>(&public).map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "invalid stored identity")
            })?;
            public.validate().map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "invalid stored identity")
            })?;
            Ok(Json(public))
        }
        None => Err(ApiError(StatusCode::NOT_FOUND, "unknown recipient")),
    }
}

/// Deliver an opaque Send blob to a recipient's inbox.
async fn send_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SendPost>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    rate_limit(&st, &email, "send", MAX_SENDS_PER_MIN)?;

    let blob_str = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "bad blob"))?;
    if blob_str.len() > MAX_SEND_BLOB {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "blob too large"));
    }
    if !valid_bastion_id(&body.recipient_id)
        || !valid_message_id(&body.message_id)
        || body.message_id != body.blob.message_id
        || body.recipient_id != body.blob.recipient_id
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad ids"));
    }
    let recipient_json = st
        .db
        .directory_lookup(&body.recipient_id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "unknown recipient"))?;
    let recipient = serde_json::from_str::<PublicIdentity>(&recipient_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "invalid stored identity"))?;
    body.blob
        .validate_for_delivery(&body.recipient_id, &recipient)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid send envelope"))?;
    let now = now_secs();
    if body.expires_at.is_some_and(|expires_at| {
        expires_at <= now || expires_at > now.saturating_add(MAX_SEND_TTL_SECS)
    }) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid expiration"));
    }
    // Per-recipient throttle (anti inbox-flood), on top of the per-sender cap.
    rate_limit(&st, &body.recipient_id, "inbound", MAX_INBOUND_PER_MIN)?;
    st.db
        .purge_expired(&body.recipient_id, now)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    // Atomic quota + dedupe (single lock → no TOCTOU).
    match st
        .db
        .insert_inbox(
            &body.message_id,
            &body.recipient_id,
            &blob_str,
            body.expires_at,
            MAX_INBOX,
        )
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        InboxInsert::Inserted => Ok(StatusCode::NO_CONTENT),
        InboxInsert::Duplicate => Err(ApiError(StatusCode::CONFLICT, "duplicate message")),
        InboxInsert::Full => Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "recipient inbox full",
        )),
    }
}

/// Pull the caller's inbox (blobs addressed to their Bastion ID).
async fn send_inbox(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InboxItem>>, ApiError> {
    let email = require_auth(&st, &headers)?;
    rate_limit(&st, &email, "inbox-read", MAX_INBOX_READS_PER_MIN)?;
    let mine = st
        .db
        .bastion_id_for(&email)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no identity published"))?;
    let now = now_secs();
    st.db
        .purge_expired(&mine, now)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let items = st
        .db
        .inbox_list(&mine, now)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(Json(items))
}

/// Delete a message from the caller's inbox (read-once / after processing).
async fn send_inbox_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    if !valid_message_id(&message_id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad message id"));
    }
    let mine = st
        .db
        .bastion_id_for(&email)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no identity published"))?;
    st.db
        .inbox_delete(&message_id, &mine)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_pragmas_are_hardened() {
        let db = Db::open(":memory:");
        let conn = db.lock();
        let busy_timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000);
        // 1 = NORMAL, the recommended durable setting under WAL.
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 1);
    }
}

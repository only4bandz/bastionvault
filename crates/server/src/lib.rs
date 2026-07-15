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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crypto_core::{EncryptedBlob, KdfParams, Registration};

/// Default session token lifetime (30 min).
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// Maximum request body size (1 MiB) — guardrail against memory DoS.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Bastion Send: max stored blob size, per-recipient inbox cap, and per-account
/// fixed-window rate limits (abuse controls — see docs/bastion-send-design.md §8).
const MAX_SEND_BLOB: usize = 256 * 1024;
const MAX_INBOX: i64 = 500;
const MAX_INBOX_PAGE: i64 = 100; // cap a single inbox fetch (paginate by deleting)
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_SENDS_PER_MIN: u32 = 60; // per sender
const MAX_INBOUND_PER_MIN: u32 = 120; // per recipient (anti inbox-flood)
const MAX_LOOKUPS_PER_MIN: u32 = 120;
const MAX_RATE_ENTRIES: usize = 100_000; // bound the in-memory rate map (anti memory-DoS)

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds the router, persisting to the SQLite database at `$BASTION_DB`
/// (default `bastion.db` in the working directory).
///
/// ⚠️ NON-PRODUCTION: this server still has NO TLS or CORS. The Bastion Send
/// endpoints have per-account rate limits + inbox quotas + size caps; the
/// account/vault endpoints still rely only on the body-size guardrail. Add
/// TLS/CORS and broader rate limiting before deployment.
pub fn app() -> Router {
    let db_path = std::env::var("BASTION_DB").unwrap_or_else(|_| "bastion.db".to_string());
    build(DEFAULT_TOKEN_TTL, &db_path)
}

/// Variant with an explicit SQLite path (used to test persistence).
pub fn app_with_db(db_path: &str) -> Router {
    build(DEFAULT_TOKEN_TTL, db_path)
}

/// In-memory (non-persistent) variant — used by tests for isolation.
pub fn app_in_memory() -> Router {
    build(DEFAULT_TOKEN_TTL, ":memory:")
}

/// In-memory variant with an explicit TTL (tests for token expiration).
pub fn app_in_memory_with_ttl(token_ttl: Duration) -> Router {
    build(token_ttl, ":memory:")
}

fn build(token_ttl: Duration, db_path: &str) -> Router {
    let state = AppState::new(token_ttl, db_path);
    Router::new()
        .route("/health", get(health))
        .route("/accounts", post(create_account))
        .route("/accounts/:email/prelogin", get(prelogin))
        .route("/sessions", post(create_session).delete(delete_session))
        .route("/vault", get(get_vault))
        .route("/vault/items/:id", put(put_item).delete(delete_item))
        .route("/vault/manifest", put(put_manifest))
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
        .with_state(state)
}

// ─── Shared state ───

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<Inner>>,
    db: Db,
    token_ttl: Duration,
}

struct Inner {
    accounts: HashMap<String, AccountRecord>, // email -> account
    sessions: HashMap<String, Session>,       // token -> session
    rate: HashMap<String, RateState>,         // "email:bucket" -> fixed-window counter
}

/// Fixed-window rate counter.
struct RateState {
    window_start: Instant,
    count: u32,
}

/// Active session: the token's owner and its expiration instant.
struct Session {
    email: String,
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
    manifest: Option<EncryptedBlob>,
}

impl AppState {
    fn new(token_ttl: Duration, db_path: &str) -> Self {
        let db = Db::open(db_path);
        let accounts = db.load_accounts();
        Self {
            inner: Arc::new(RwLock::new(Inner {
                accounts,
                sessions: HashMap::new(),
                rate: HashMap::new(),
            })),
            db,
            token_ttl,
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

impl Db {
    fn open(path: &str) -> Self {
        let conn = Connection::open(path).expect("open database");
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS accounts(
               email TEXT PRIMARY KEY, salt TEXT NOT NULL, kdf TEXT NOT NULL,
               wrapped_vault_key TEXT NOT NULL, auth_hash TEXT NOT NULL);
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

    fn put_item(&self, email: &str, id: &str, blob_json: &str) -> rusqlite::Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO items(email,id,blob) VALUES(?1,?2,?3)",
            params![email, id, blob_json],
        )?;
        Ok(())
    }

    fn delete_item(&self, email: &str, id: &str) -> rusqlite::Result<()> {
        self.lock().execute(
            "DELETE FROM items WHERE email=?1 AND id=?2",
            params![email, id],
        )?;
        Ok(())
    }

    fn put_manifest(&self, email: &str, blob_json: &str) -> rusqlite::Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO manifests(email,blob) VALUES(?1,?2)",
            params![email, blob_json],
        )?;
        Ok(())
    }

    /// Loads all accounts (with their items and manifest) at startup.
    fn load_accounts(&self) -> HashMap<String, AccountRecord> {
        let conn = self.lock();
        let mut accounts: HashMap<String, AccountRecord> = HashMap::new();

        {
            let mut stmt = conn
                .prepare("SELECT email,salt,kdf,wrapped_vault_key,auth_hash FROM accounts")
                .expect("prepare accounts");
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .expect("query accounts");
            for (email, salt, kdf_s, wrapped_s, auth_hash) in rows.flatten() {
                let kdf: KdfParams = match serde_json::from_str(&kdf_s) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                let wrapped_vault_key: EncryptedBlob = match serde_json::from_str(&wrapped_s) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                accounts.insert(
                    email,
                    AccountRecord {
                        salt,
                        kdf,
                        wrapped_vault_key,
                        auth_hash,
                        items: HashMap::new(),
                        manifest: None,
                    },
                );
            }
        }
        {
            let mut stmt = conn
                .prepare("SELECT email,id,blob FROM items")
                .expect("prepare items");
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .expect("query items");
            for (email, id, blob_s) in rows.flatten() {
                if let Some(acc) = accounts.get_mut(&email) {
                    if let Ok(blob) = serde_json::from_str(&blob_s) {
                        acc.items.insert(id, blob);
                    }
                }
            }
        }
        {
            let mut stmt = conn
                .prepare("SELECT email,blob FROM manifests")
                .expect("prepare manifests");
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .expect("query manifests");
            for (email, blob_s) in rows.flatten() {
                if let Some(acc) = accounts.get_mut(&email) {
                    acc.manifest = serde_json::from_str(&blob_s).ok();
                }
            }
        }
        accounts
    }
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
    auth_secret: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct VaultResponse {
    items: HashMap<String, EncryptedBlob>,
    manifest: Option<EncryptedBlob>,
}

#[derive(Deserialize)]
struct BlobBody {
    blob: EncryptedBlob,
}

// ─── Handlers ───

async fn health() -> &'static str {
    "ok"
}

async fn create_account(
    State(st): State<AppState>,
    Json(req): Json<CreateAccount>,
) -> Result<StatusCode, ApiError> {
    // Reject a known duplicate before paying the Argon2 cost. The authoritative
    // collision check is repeated under the write lock after hashing.
    if st.read().accounts.contains_key(&req.email) {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    // Slow hash on a dedicated blocking thread (no starvation of the async runtime).
    let secret = req.registration.auth_secret.expose_b64().to_string();
    let auth_hash = tokio::task::spawn_blocking(move || hash_secret(&secret))
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
            manifest: None,
        },
    );
    Ok(StatusCode::CREATED)
}

async fn prelogin(
    State(st): State<AppState>,
    Path(email): Path<String>,
) -> Result<Json<Prelogin>, ApiError> {
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
    // We copy the hash, then release the lock before the slow verification.
    let phc = st
        .read()
        .accounts
        .get(&req.email)
        .map(|a| a.auth_hash.clone());
    // Same response for "unknown account" and "wrong secret".
    let phc = phc.ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let secret = req.auth_secret.clone();
    let ok = tokio::task::spawn_blocking(move || verify_secret(&secret, &phc))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "join error"))?;
    if !ok {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let token = new_token();
    let expires_at = Instant::now() + st.token_ttl;
    st.write().sessions.insert(
        token.clone(),
        Session {
            email: req.email,
            expires_at,
        },
    );
    Ok(Json(LoginResponse { token }))
}

async fn get_vault(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultResponse>, ApiError> {
    let email = require_auth(&st, &headers)?;
    let inner = st.read();
    let acc = inner
        .accounts
        .get(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    Ok(Json(VaultResponse {
        items: acc.items.clone(),
        manifest: acc.manifest.clone(),
    }))
}

async fn put_item(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<BlobBody>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    let blob_json = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    // Keep persistence and the read cache in one ordered critical section. If
    // concurrent requests write the same id, the cache winner must be the same
    // request as the SQLite winner.
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    st.db
        .put_item(&email, &id, &blob_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    acc.items.insert(id, body.blob);
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_item(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    st.db
        .delete_item(&email, &id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    acc.items.remove(&id);
    Ok(StatusCode::NO_CONTENT)
}

async fn put_manifest(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BlobBody>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    let blob_json = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    st.db
        .put_manifest(&email, &blob_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    acc.manifest = Some(body.blob);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Helpers ───

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

/// Slow Argon2id hash (PHC) of the authentication secret.
fn hash_secret(secret: &str) -> Result<String, ()> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ())
}

/// Verifies a secret against a PHC hash, in constant time (via `argon2`).
fn verify_secret(secret: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
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

/// Fixed-window per-account rate limit. `bucket` separates send vs lookup.
fn rate_limit(st: &AppState, email: &str, bucket: &str, max: u32) -> Result<(), ApiError> {
    let key = format!("{email}:{bucket}");
    let mut inner = st.write();
    let now = Instant::now();
    // Bound the map: when large, drop entries whose window has elapsed
    // (anti memory-DoS via many accounts).
    if inner.rate.len() > MAX_RATE_ENTRIES {
        inner
            .rate
            .retain(|_, v| now.duration_since(v.window_start) <= RATE_WINDOW);
    }
    let e = inner.rate.entry(key).or_insert(RateState {
        window_start: now,
        count: 0,
    });
    if now.duration_since(e.window_start) > RATE_WINDOW {
        e.window_start = now;
        e.count = 0;
    }
    e.count += 1;
    if e.count > max {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    Ok(())
}

impl Db {
    /// Upsert the caller's published identity, keeping a stable bastion_id.
    fn publish_identity(&self, email: &str, public_json: &str) -> rusqlite::Result<String> {
        let conn = self.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT bastion_id FROM send_directory WHERE email=?1",
                [email],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            // Rotation: keep the stable bastion_id, just replace the public part.
            conn.execute(
                "UPDATE send_directory SET public=?2 WHERE email=?1",
                params![email, public_json],
            )?;
            return Ok(id);
        }
        // New account: retry generation on the (astronomically rare) id collision.
        for _ in 0..8 {
            let id = new_bastion_id();
            match conn.execute(
                "INSERT INTO send_directory(email, bastion_id, public, created_at) VALUES(?1,?2,?3,?4)",
                params![email, id, public_json, now_secs()],
            ) {
                Ok(_) => return Ok(id),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    continue
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

    fn recipient_exists(&self, bastion_id: &str) -> rusqlite::Result<bool> {
        Ok(self
            .lock()
            .query_row(
                "SELECT 1 FROM send_directory WHERE bastion_id=?1",
                [bastion_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
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

    fn purge_expired(&self, now: i64) {
        let _ = self.lock().execute(
            "DELETE FROM send_inbox WHERE expires_at IS NOT NULL AND expires_at < ?1",
            [now],
        );
    }

    fn inbox_list(&self, recipient_id: &str, now: i64) -> rusqlite::Result<Vec<InboxItem>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT message_id, blob, created_at, expires_at FROM send_inbox
             WHERE recipient_id=?1 AND (expires_at IS NULL OR expires_at >= ?2)
             ORDER BY created_at ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![recipient_id, now, MAX_INBOX_PAGE], |r| {
            Ok(InboxItem {
                message_id: r.get(0)?,
                blob: serde_json::from_str(&r.get::<_, String>(1)?)
                    .unwrap_or(serde_json::Value::Null),
                created_at: r.get(2)?,
                expires_at: r.get(3)?,
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
    public: serde_json::Value,
}

#[derive(Serialize)]
struct PublishResponse {
    bastion_id: String,
}

#[derive(Deserialize)]
struct SendPost {
    recipient_id: String,
    message_id: String,
    blob: serde_json::Value,
    expires_at: Option<i64>,
}

#[derive(Serialize)]
struct InboxItem {
    message_id: String,
    blob: serde_json::Value,
    created_at: i64,
    expires_at: Option<i64>,
}

/// Outcome of an atomic inbox insert (quota + dedupe checked under one lock).
enum InboxInsert {
    Inserted,
    Duplicate,
    Full,
}

/// Publish (or rotate) the caller's Send identity. Body = the PublicIdentity
/// JSON (opaque to the server). Returns the stable Bastion ID.
async fn publish_identity(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(public): Json<serde_json::Value>,
) -> Result<Json<PublishResponse>, ApiError> {
    let email = require_auth(&st, &headers)?;
    let public_json = serde_json::to_string(&public)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "bad json"))?;
    if public_json.len() > MAX_SEND_BLOB {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "identity too large",
        ));
    }
    let bastion_id = st
        .db
        .publish_identity(&email, &public_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(Json(PublishResponse { bastion_id }))
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
        Some((bastion_id, public)) => Ok(Json(WhoAmI {
            bastion_id,
            public: serde_json::from_str(&public).unwrap_or(serde_json::Value::Null),
        })),
        None => Err(ApiError(StatusCode::NOT_FOUND, "no identity published")),
    }
}

/// Resolve a Bastion ID to its public identity. Authenticated, exact-match,
/// rate-limited (no enumeration).
async fn send_directory(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(bastion_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = require_auth(&st, &headers)?;
    rate_limit(&st, &email, "lookup", MAX_LOOKUPS_PER_MIN)?;
    match st
        .db
        .directory_lookup(&bastion_id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        Some(public) => Ok(Json(
            serde_json::from_str(&public).unwrap_or(serde_json::Value::Null),
        )),
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
    if body.message_id.is_empty() || body.message_id.len() > 128 || body.recipient_id.len() > 128 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad ids"));
    }
    if !st
        .db
        .recipient_exists(&body.recipient_id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "unknown recipient"));
    }
    // Per-recipient throttle (anti inbox-flood), on top of the per-sender cap.
    rate_limit(&st, &body.recipient_id, "inbound", MAX_INBOUND_PER_MIN)?;
    st.db.purge_expired(now_secs());
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
    let mine = st
        .db
        .bastion_id_for(&email)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no identity published"))?;
    let now = now_secs();
    st.db.purge_expired(now);
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

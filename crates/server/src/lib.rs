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
use std::time::{Duration, Instant};

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

/// Builds the router, persisting to the SQLite database at `$BASTION_DB`
/// (default `bastion.db` in the working directory).
///
/// ⚠️ NON-PRODUCTION: this server still has NO TLS, CORS, rate limiting, or
/// storage quotas. These controls must be added (and tested) before deployment.
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
        .route("/bin/:bin", get(get_bin))
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
             CREATE TABLE IF NOT EXISTS bins(
               bin TEXT PRIMARY KEY, scheme TEXT, bank_name TEXT);",
        )
        .expect("init schema");
        // Add the debit/credit column to pre-existing bin caches (no-op if present).
        let _ = conn.execute("ALTER TABLE bins ADD COLUMN card_type TEXT", []);
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save_account(
        &self,
        email: &str,
        salt: &str,
        kdf_json: &str,
        wrapped_json: &str,
        auth_hash: &str,
    ) -> rusqlite::Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO accounts(email,salt,kdf,wrapped_vault_key,auth_hash) \
             VALUES(?1,?2,?3,?4,?5)",
            params![email, salt, kdf_json, wrapped_json, auth_hash],
        )?;
        Ok(())
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

    fn get_bin(&self, bin: &str) -> Option<BinInfo> {
        self.lock()
            .query_row(
                "SELECT scheme,bank_name,card_type FROM bins WHERE bin=?1",
                params![bin],
                |r| {
                    Ok(BinInfo {
                        scheme: r.get::<_, Option<String>>(0)?,
                        bank_name: r.get::<_, Option<String>>(1)?,
                        card_type: r.get::<_, Option<String>>(2)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn put_bin(&self, bin: &str, info: &BinInfo) -> rusqlite::Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO bins(bin,scheme,bank_name,card_type) VALUES(?1,?2,?3,?4)",
            params![bin, info.scheme, info.bank_name, info.card_type],
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

/// Issuing-bank info for a card BIN (network + bank name + debit/credit).
/// Never the full card.
#[derive(Serialize, Clone, Default)]
struct BinInfo {
    scheme: Option<String>,
    bank_name: Option<String>,
    card_type: Option<String>, // "debit" | "credit"
}

// ─── Handlers ───

async fn health() -> &'static str {
    "ok"
}

async fn create_account(
    State(st): State<AppState>,
    Json(req): Json<CreateAccount>,
) -> Result<StatusCode, ApiError> {
    // Slow hash on a dedicated blocking thread (no starvation of the async runtime).
    let secret = req.registration.auth_secret.expose_b64().to_string();
    let auth_hash = tokio::task::spawn_blocking(move || hash_secret(&secret))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "join error"))?
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "hash failure"))?;

    if st.read().accounts.contains_key(&req.email) {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    let kdf_json = serde_json::to_string(&req.registration.kdf)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    let wrapped_json = serde_json::to_string(&req.registration.wrapped_vault_key)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    // Persist first (source of truth), then update the in-memory cache.
    st.db
        .save_account(
            &req.email,
            &req.registration.salt,
            &kdf_json,
            &wrapped_json,
            &auth_hash,
        )
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    st.write().accounts.insert(
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
    if !st.read().accounts.contains_key(&email) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    st.db
        .put_item(&email, &id, &blob_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    if let Some(acc) = st.write().accounts.get_mut(&email) {
        acc.items.insert(id, body.blob);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_item(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    st.db
        .delete_item(&email, &id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    if let Some(acc) = st.write().accounts.get_mut(&email) {
        acc.items.remove(&id);
    }
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
    if !st.read().accounts.contains_key(&email) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    st.db
        .put_manifest(&email, &blob_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    if let Some(acc) = st.write().accounts.get_mut(&email) {
        acc.manifest = Some(body.blob);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Resolves a card BIN to its network + issuing bank, cached in SQLite so any
/// given BIN hits the upstream service at most once. Unauthenticated — BIN data
/// is not secret, and only the BIN (never the full card) is involved.
async fn get_bin(State(st): State<AppState>, Path(bin): Path<String>) -> Json<BinInfo> {
    let bin: String = bin.chars().filter(|c| c.is_ascii_digit()).take(8).collect();
    if bin.len() < 6 {
        return Json(BinInfo::default());
    }
    if let Some(info) = st.db.get_bin(&bin) {
        return Json(info);
    }
    match fetch_binlist(&bin).await {
        Some(info) => {
            let _ = st.db.put_bin(&bin, &info);
            Json(info)
        }
        // Don't cache failures (e.g. upstream rate limit) — retry next time.
        None => Json(BinInfo::default()),
    }
}

/// Best-effort upstream BIN lookup (binlist). Returns `None` on any non-success.
async fn fetch_binlist(bin: &str) -> Option<BinInfo> {
    let url = format!("https://lookup.binlist.net/{bin}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let j: serde_json::Value = resp.json().await.ok()?;
    Some(BinInfo {
        scheme: j.get("scheme").and_then(|v| v.as_str()).map(String::from),
        bank_name: j
            .get("bank")
            .and_then(|b| b.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from),
        card_type: j.get("type").and_then(|v| v.as_str()).map(String::from),
    })
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

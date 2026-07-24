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

mod mail_outbox;

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params as ArgonParams};
use axum::extract::{DefaultBodyLimit, Extension, Path, Request, State};
use axum::http::{header, uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    Engine,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{
    mpsc, oneshot, OwnedSemaphorePermit, RwLock, RwLockReadGuard, RwLockWriteGuard, Semaphore,
};
use zeroize::Zeroize;

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
const MAX_VAULT_REVISION_READS_PER_MIN: u32 = 300;
const MAX_INBOX_READS_PER_MIN: u32 = 60;
const MAX_ACCOUNT_DELETION_ATTEMPTS_PER_MIN: u32 = 5;
const MAX_RATE_ENTRIES: usize = 100_000; // bound the in-memory rate map (anti memory-DoS)
/// Maximum accepted SQLite commands waiting behind the dedicated connection
/// owner. Saturation fails fast instead of allocating unbounded work.
const DB_QUEUE_CAPACITY: usize = 256;
/// Upper bound for an accepted storage command to produce a response. SQLite's
/// own busy timeout is shorter, leaving headroom for queueing and validation.
const DB_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Latest schema understood by this binary. Startup refuses newer databases
/// instead of silently running code against an incompatible layout.
const CURRENT_SCHEMA_VERSION: i64 = 4;
const VERIFICATION_TOKEN_BYTES: usize = 32;
const VERIFICATION_TTL_SECONDS: i64 = 30 * 60;
const VERIFICATION_RESEND_SECONDS: i64 = 2 * 60;
const MAX_CHALLENGES_GLOBAL_PER_MIN: u32 = 30;
const MAX_CHALLENGES_PER_EMAIL_PER_MIN: u32 = 2;
const MAX_VERIFICATIONS_GLOBAL_PER_MIN: u32 = 120;
const MAX_VERIFICATIONS_PER_TOKEN_PER_MIN: u32 = 5;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7777";
const DEFAULT_DB_PATH: &str = "bastion.db";
const FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";

/// Validated process configuration. Production is deliberately narrower than
/// development: a same-host TLS ingress is public and Axum stays on loopback.
#[derive(Clone)]
pub struct ServerConfig {
    bind_addr: SocketAddr,
    db_path: String,
    transport: Option<TransportPolicy>,
    smtp: Option<mail_outbox::SmtpConfig>,
}

#[derive(Clone, Debug)]
struct TransportPolicy {
    public_origin: String,
    public_authority: Authority,
}

impl ServerConfig {
    /// Read and validate the environment before opening storage or a socket.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self, String> {
        let mode = lookup("BASTION_ENV").unwrap_or_else(|| "development".to_string());
        let smtp = mail_outbox::SmtpConfig::from_lookup(&mut lookup)?;
        match mode.as_str() {
            "development" => Ok(Self {
                bind_addr: parse_bind_addr(
                    lookup("BIND_ADDR").as_deref().unwrap_or(DEFAULT_BIND_ADDR),
                )?,
                db_path: lookup("BASTION_DB").unwrap_or_else(|| DEFAULT_DB_PATH.to_string()),
                transport: None,
                smtp,
            }),
            "production" => {
                let bind_addr = parse_bind_addr(&required_setting(&mut lookup, "BIND_ADDR")?)?;
                if !bind_addr.ip().is_loopback() {
                    return Err(
                        "production BIND_ADDR must be loopback; public or unauthenticated private Axum listeners are unsupported"
                            .to_string(),
                    );
                }
                let db_path = required_setting(&mut lookup, "BASTION_DB")?;
                if db_path == ":memory:" || !FsPath::new(&db_path).is_absolute() {
                    return Err(
                        "production BASTION_DB must be an absolute persistent filesystem path"
                            .to_string(),
                    );
                }
                let public_origin = required_setting(&mut lookup, "BASTION_PUBLIC_ORIGIN")?;
                let transport = TransportPolicy::parse(&public_origin)?;
                let smtp = smtp.ok_or_else(|| {
                    "complete SMTP configuration is required when BASTION_ENV=production"
                        .to_string()
                })?;
                Ok(Self {
                    bind_addr,
                    db_path,
                    transport: Some(transport),
                    smtp: Some(smtp),
                })
            }
            _ => Err("BASTION_ENV must be either development or production".to_string()),
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    pub fn is_production(&self) -> bool {
        self.transport.is_some()
    }

    pub fn public_origin(&self) -> Option<&str> {
        self.transport
            .as_ref()
            .map(|policy| policy.public_origin.as_str())
    }
}

fn required_setting(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &str,
) -> Result<String, String> {
    lookup(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required when BASTION_ENV=production"))
}

fn parse_bind_addr(value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| "BIND_ADDR must be a numeric IP socket address".to_string())
}

impl TransportPolicy {
    fn parse(value: &str) -> Result<Self, String> {
        if value.trim() != value || !value.is_ascii() {
            return Err("BASTION_PUBLIC_ORIGIN must be a canonical ASCII HTTPS origin".to_string());
        }
        let uri: Uri = value.parse().map_err(|_| {
            "BASTION_PUBLIC_ORIGIN must be a valid absolute HTTPS origin".to_string()
        })?;
        if uri.scheme_str() != Some("https")
            || uri.authority().is_none()
            || uri.query().is_some()
            || !matches!(uri.path(), "" | "/")
        {
            return Err(
                "BASTION_PUBLIC_ORIGIN must contain only an HTTPS origin without path, query, or fragment"
                    .to_string(),
            );
        }
        let authority = uri.authority().cloned().expect("authority checked");
        if authority.as_str().contains('@') || authority.host().is_empty() {
            return Err("BASTION_PUBLIC_ORIGIN must not contain credentials".to_string());
        }
        if authority.port_u16() == Some(443) {
            return Err("BASTION_PUBLIC_ORIGIN must omit the default HTTPS port 443".to_string());
        }
        let canonical_authority = Authority::from_str(&authority.as_str().to_ascii_lowercase())
            .map_err(|_| "BASTION_PUBLIC_ORIGIN has an invalid authority".to_string())?;
        let public_origin = format!("https://{canonical_authority}");
        if value.trim_end_matches('/') != public_origin {
            return Err(format!(
                "BASTION_PUBLIC_ORIGIN must be canonical; use {public_origin}"
            ));
        }
        Ok(Self {
            public_origin,
            public_authority: canonical_authority,
        })
    }

    fn accepts_host(&self, value: &HeaderValue) -> bool {
        value
            .to_str()
            .ok()
            .and_then(|raw| Authority::from_str(raw).ok())
            .is_some_and(|actual| {
                actual
                    .host()
                    .eq_ignore_ascii_case(self.public_authority.host())
                    && actual.port_u16() == self.public_authority.port_u16()
            })
    }
}

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

/// Builds the development router, persisting to the SQLite database at
/// `$BASTION_DB` (default `bastion.db` in the working directory).
pub fn app() -> Router {
    let db_path = env::var("BASTION_DB").unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());
    build(DEFAULT_TOKEN_TTL, &db_path, MAX_CONCURRENT_AUTH)
}

/// Builds a router from startup settings that already failed closed on an
/// invalid production transport or storage contract.
pub fn app_with_config(config: &ServerConfig) -> Router {
    build_with_transport(
        DEFAULT_TOKEN_TTL,
        config.db_path(),
        MAX_CONCURRENT_AUTH,
        config.transport.clone(),
        config.smtp.clone(),
    )
}

/// Variant with an explicit SQLite path (used to test persistence).
pub fn app_with_db(db_path: &str) -> Router {
    build(DEFAULT_TOKEN_TTL, db_path, MAX_CONCURRENT_AUTH)
}

/// Test-only topology for exercising mailbox proof without contacting an SMTP
/// relay. Production obtains this policy only through validated `ServerConfig`.
#[doc(hidden)]
pub fn app_with_db_and_mailbox_verification(db_path: &str, origin: &str) -> Router {
    build_with_rate_limits(
        DEFAULT_TOKEN_TTL,
        db_path,
        MAX_CONCURRENT_AUTH,
        RuntimeOptions {
            verification_origin: Some(origin.to_string()),
            ..RuntimeOptions::default()
        },
    )
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
        RuntimeOptions {
            max_rate_entries: max_entries,
            rate_window: window,
            ..RuntimeOptions::default()
        },
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
        RuntimeOptions {
            auth_rate_limits: limits,
            ..RuntimeOptions::default()
        },
    )
}

struct RuntimeOptions {
    max_rate_entries: usize,
    rate_window: Duration,
    auth_rate_limits: AuthRateLimits,
    transport: Option<TransportPolicy>,
    smtp: Option<mail_outbox::SmtpConfig>,
    verification_origin: Option<String>,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            max_rate_entries: MAX_RATE_ENTRIES,
            rate_window: RATE_WINDOW,
            auth_rate_limits: AuthRateLimits::default(),
            transport: None,
            smtp: None,
            verification_origin: None,
        }
    }
}

fn build(token_ttl: Duration, db_path: &str, auth_limit: usize) -> Router {
    build_with_transport(token_ttl, db_path, auth_limit, None, None)
}

fn build_with_transport(
    token_ttl: Duration,
    db_path: &str,
    auth_limit: usize,
    transport: Option<TransportPolicy>,
    smtp: Option<mail_outbox::SmtpConfig>,
) -> Router {
    let verification_origin = transport
        .as_ref()
        .map(|policy| policy.public_origin.clone());
    build_with_rate_limits(
        token_ttl,
        db_path,
        auth_limit,
        RuntimeOptions {
            transport,
            smtp,
            verification_origin,
            ..RuntimeOptions::default()
        },
    )
}

fn build_with_rate_limits(
    token_ttl: Duration,
    db_path: &str,
    auth_limit: usize,
    options: RuntimeOptions,
) -> Router {
    let state = AppState::new(token_ttl, db_path, auth_limit, options);
    let transaction_route = put(apply_vault_transaction)
        .layer(DefaultBodyLimit::max(MAX_VAULT_TRANSACTION_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_vault_transaction,
        ));
    let protected_routes = Router::new()
        .route("/accounts", post(create_account).delete(delete_account))
        .route("/accounts/:email/prelogin", get(prelogin))
        .route(
            "/registration-challenges",
            post(request_registration_challenge),
        )
        .route(
            "/registration-challenges/verify",
            post(verify_registration_challenge),
        )
        .route("/sessions", post(create_session).delete(delete_session))
        .route("/vault", get(get_vault))
        .route("/vault/revision", get(get_vault_revision))
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            storage_availability_gate,
        ));
    let routes = Router::new()
        .route("/config", get(public_config))
        .route("/health", get(health))
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .merge(protected_routes);
    let legacy = routes
        .clone()
        .layer(middleware::from_fn(legacy_api_headers));
    Router::new()
        .merge(legacy)
        .nest("/v1", routes)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            production_transport_boundary,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(middleware::from_fn(request_log))
        .with_state(state)
}

async fn storage_availability_gate(
    State(st): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !st.db.is_available() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage unavailable",
        ));
    }
    Ok(next.run(request).await)
}

async fn legacy_api_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("deprecation", HeaderValue::from_static("true"));
    response.headers_mut().insert(
        header::LINK,
        HeaderValue::from_static("</v1>; rel=\"successor-version\""),
    );
    response
}

/// Stamps defensive headers on every response, including errors.
///
/// The API serves bearer tokens, wrapped vault keys and encrypted blobs; none
/// of it may ever land in a shared cache or be sniffed/framed by a browser.
/// Redacts the dynamic segment of routes whose path carries user data, so the
/// request log never records an email address (`/accounts/:email/prelogin`) or
/// an opaque routing id. Everything else is a fixed route shape.
fn redacted_path(path: &str) -> String {
    if let Some(versioned) = path.strip_prefix("/v1") {
        return format!("/v1{}", redacted_path(versioned));
    }
    if path.starts_with("/accounts/") && path.ends_with("/prelogin") {
        return "/accounts/{email}/prelogin".to_string();
    }
    if let Some(rest) = path.strip_prefix("/send/directory/") {
        if !rest.is_empty() {
            return "/send/directory/{id}".to_string();
        }
    }
    if let Some(rest) = path.strip_prefix("/send/inbox/") {
        if !rest.is_empty() {
            return "/send/inbox/{id}".to_string();
        }
    }
    if let Some(rest) = path.strip_prefix("/vault/items/") {
        if !rest.is_empty() {
            return "/vault/items/{id}".to_string();
        }
    }
    path.to_string()
}

/// One structured line per request: method, redacted route, status. 5xx are
/// logged at error, everything else at info. No request/response bodies, no
/// headers — nothing secret is ever recorded.
async fn request_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = redacted_path(request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if response.status().is_server_error() {
        tracing::error!(%method, path, status, latency_ms, "request");
    } else {
        tracing::info!(%method, path, status, latency_ms, "request");
    }
    response
}

fn direct_health_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/livez" | "/readyz" | "/v1/health" | "/v1/livez" | "/v1/readyz"
    )
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

async fn production_transport_boundary(
    State(st): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(policy) = &st.transport else {
        return Ok(next.run(request).await);
    };

    // Private health probes intentionally run directly over loopback. Every
    // application request must cross the same-host TLS ingress, which preserves
    // the public Host and stamps one trusted HTTPS proto value.
    if direct_health_path(request.uri().path()) {
        return Ok(next.run(request).await);
    }
    if !single_header(request.headers(), header::HOST.as_str())
        .is_some_and(|host| policy.accepts_host(host))
    {
        return Err(ApiError(
            StatusCode::MISDIRECTED_REQUEST,
            "wrong public host",
        ));
    }
    if single_header(request.headers(), FORWARDED_PROTO_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some("https")
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "trusted ingress did not attest HTTPS",
        ));
    }
    Ok(next.run(request).await)
}

async fn security_headers(State(st): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    // Fixed-window limiters: retrying after a full window is always safe.
    // Advertise that upper bound so well-behaved clients back off instead of
    // hammering, per RFC 9110 §10.2.3.
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let window = st.rate_window.max(st.auth_rate_limits.window);
        if let Ok(value) = HeaderValue::from_str(&window.as_secs().max(1).to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
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
    // The API serves JSON only. A no-op CSP for JSON, but if any response is
    // ever coerced into a document context (sniffing bug, error-page quirk),
    // nothing loads, nothing runs, and no page may frame it.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    // Deny every powerful browser feature to documents born from API bytes.
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    // Isolate any such document from cross-origin windows and embedders.
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "x-permitted-cross-domain-policies",
        HeaderValue::from_static("none"),
    );
    if st.transport.is_some() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
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
    transport: Option<TransportPolicy>,
    verification_origin: Option<String>,
    /// Per-deployment secret keying deterministic prelogin decoys.
    prelogin_decoy_seed: [u8; 32],
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
    email_verified_at: Option<i64>,
    items: HashMap<String, EncryptedBlob>,
    item_bytes: HashMap<String, usize>,
    manifest: Option<EncryptedBlob>,
    manifest_bytes: usize,
    stored_bytes: usize,
    vault_revision: u64,
}

impl AppState {
    fn new(token_ttl: Duration, db_path: &str, auth_limit: usize, options: RuntimeOptions) -> Self {
        let RuntimeOptions {
            max_rate_entries,
            rate_window,
            auth_rate_limits,
            transport,
            smtp,
            verification_origin,
        } = options;
        let (db, accounts, prelogin_decoy_seed) = Db::open(db_path);
        let state = Self {
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
            transport,
            verification_origin,
            prelogin_decoy_seed,
        };
        if let Some(config) = smtp {
            mail_outbox::spawn(state.db.clone(), config);
        }
        state
    }

    /// Tokio-aware state locks preserve cache/database ordering without
    /// blocking an executor thread while the storage owner is working.
    async fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().await
    }

    /// Mutations hold this logical lock across their awaited database command
    /// so the write-through cache cannot become observably inconsistent.
    async fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().await
    }
}

// ─── SQLite persistence (write-through; the in-memory cache backs reads) ───

#[derive(Clone)]
struct Db {
    // Field order matters on final drop: close the last sender before joining
    // the worker, allowing blocking_recv() to finish.
    sender: mpsc::Sender<DbJob>,
    _worker: Arc<DbWorker>,
    available: Arc<AtomicBool>,
    response_timeout: Duration,
}

type DbJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

struct DbWorker {
    join: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for DbWorker {
    fn drop(&mut self) {
        if let Some(join) = self
            .join
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            // All Db senders have gone away before the final worker Arc, so the
            // receive loop can drain accepted commands and exit deterministically.
            let _ = join.join();
        }
    }
}

#[derive(Debug)]
enum DbError {
    Sqlite,
    QueueFull,
    WorkerClosed,
    ResponseTimeout,
    Quarantined,
}

#[derive(Clone)]
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

struct RegistrationMail {
    outbox_id: String,
    recipient: String,
    subject: String,
    text_body: String,
    token_hash: [u8; 32],
    expires_at: i64,
    resend_after: i64,
    created_at: i64,
}

enum ChallengeRequestOutcome {
    Queued,
    Noop,
    QueueFull,
}

enum AccountCreateOutcome {
    Created,
    Conflict,
    InvalidMailboxProof,
}

struct NewAccount {
    email: String,
    salt: String,
    kdf_json: String,
    wrapped_json: String,
    auth_hash: String,
    mailbox_proof: Option<[u8; 32]>,
    created_at: i64,
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
    for suffix in ["-wal", "-shm", "-journal", "-server.lock"] {
        secure_database_artifact(&sqlite_artifact_path(path, suffix), false)?;
    }
    Ok(())
}

fn acquire_instance_lock(path: &FsPath) -> io::Result<File> {
    let lock_path = sqlite_artifact_path(path, "-server.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(_) => secure_database_artifact(&lock_path, true)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options.open(&lock_path)?;
            secure_database_artifact(&lock_path, true)?;
        }
        Err(error) => return Err(error),
    }

    let lock = OpenOptions::new().read(true).write(true).open(&lock_path)?;
    let opened = lock.metadata()?;
    let linked = fs::symlink_metadata(&lock_path)?;
    if !opened.is_file() || linked.file_type().is_symlink() || !linked.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server lock must remain a regular file",
        ));
    }
    #[cfg(unix)]
    if opened.dev() != linked.dev() || opened.ino() != linked.ino() || opened.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server lock changed while it was being opened",
        ));
    }
    lock.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::AddrInUse,
            "another Bastion server already owns this database",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    Ok(lock)
}

struct PartialBackup {
    path: PathBuf,
    keep: bool,
}

impl Drop for PartialBackup {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let _ = fs::remove_file(&self.path);
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(sqlite_artifact_path(&self.path, suffix));
        }
    }
}

/// Creates a coherent, no-clobber SQLite snapshot suitable for later restore.
///
/// The source may be live: SQLite's online backup API includes committed WAL
/// state without copying database files behind SQLite's back. The destination
/// must not exist, remains owner-only, and is published only after integrity,
/// foreign-key, schema-version, and filesystem durability checks pass.
///
/// The snapshot still contains sensitive account metadata and verifier
/// material. Operators must encrypt it before transferring it off-host.
pub fn backup_database(
    source: &FsPath,
    destination: &FsPath,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    secure_database_parent(source)?;
    secure_database_artifacts(source)?;
    secure_database_parent(destination)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "backup destination already exists",
            )
            .into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let destination_parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| FsPath::new("."));
    let destination_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup destination must name a file",
        )
    })?;
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let partial_name = format!(
        ".{}.partial-{}",
        destination_name.to_string_lossy(),
        data_encoding::HEXLOWER.encode(&random)
    );
    let partial_path = destination_parent.join(partial_name);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(&partial_path)?;
    let mut partial = PartialBackup {
        path: partial_path.clone(),
        keep: false,
    };

    let source_conn = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    source_conn.busy_timeout(Duration::from_secs(5))?;
    let source_version: i64 = source_conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if source_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "source schema version {source_version} does not match supported version {CURRENT_SCHEMA_VERSION}"
            ),
        )
        .into());
    }

    let mut destination_conn = Connection::open_with_flags(
        &partial_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    {
        let backup = rusqlite::backup::Backup::new(&source_conn, &mut destination_conn)?;
        backup.run_to_completion(128, Duration::from_millis(10), None)?;
    }
    let integrity: String =
        destination_conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "backup failed SQLite integrity_check",
        )
        .into());
    }
    destination_conn.pragma_update(None, "foreign_keys", "ON")?;
    let has_violation = {
        let mut stmt = destination_conn.prepare("PRAGMA foreign_key_check")?;
        let violation = stmt.query([])?.next()?.is_some();
        violation
    };
    if has_violation {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "backup failed SQLite foreign_key_check",
        )
        .into());
    }
    let backup_version: i64 =
        destination_conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if backup_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "backup schema version changed during snapshot",
        )
        .into());
    }
    destination_conn.execute_batch(
        "PRAGMA wal_checkpoint(TRUNCATE);
         PRAGMA journal_mode=DELETE;",
    )?;
    drop(destination_conn);
    drop(source_conn);

    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = sqlite_artifact_path(&partial_path, suffix);
        match fs::remove_file(sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    secure_database_artifact(&partial_path, true)?;
    File::open(&partial_path)?.sync_all()?;
    // hard_link is an atomic no-clobber publication on the same filesystem.
    // Removing the private partial name leaves exactly one link, satisfying
    // the server's hard-link defense without ever replacing an existing backup.
    fs::hard_link(&partial_path, destination)?;
    fs::remove_file(&partial_path)?;
    partial.keep = true;
    secure_database_artifact(destination, true)?;
    File::open(destination)?.sync_all()?;
    #[cfg(unix)]
    File::open(destination_parent)?.sync_all()?;
    Ok(())
}

/// Aggregate, non-secret operational state from a live or restored database.
///
/// This opens SQLite read-only and does not acquire the server ownership lock,
/// so an operator can poll a live WAL database without creating a second
/// writer. The result deliberately excludes account identifiers, routing ids,
/// token material, message bodies, and ciphertext metadata.
#[derive(Debug, Serialize)]
pub struct OperationalSnapshot {
    pub observed_at: i64,
    pub schema_version: i64,
    pub database_bytes: u64,
    pub accounts: i64,
    pub registration_challenges_active: i64,
    pub registration_challenges_verified: i64,
    pub registration_challenges_expired: i64,
    pub mail_pending: i64,
    pub mail_in_flight: i64,
    pub mail_dead: i64,
    pub oldest_active_mail_age_seconds: Option<i64>,
}

pub fn operational_snapshot(
    database: &FsPath,
) -> Result<OperationalSnapshot, Box<dyn std::error::Error + Send + Sync>> {
    secure_database_parent(database)?;
    secure_database_artifacts(database)?;
    let conn = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "database schema version {schema_version} does not match supported version {CURRENT_SCHEMA_VERSION}"
            ),
        )
        .into());
    }
    let observed_at = now_secs();
    let (
        accounts,
        registration_challenges_active,
        registration_challenges_verified,
        registration_challenges_expired,
        mail_pending,
        mail_in_flight,
        mail_dead,
        oldest_active_created_at,
    ): (i64, i64, i64, i64, i64, i64, i64, Option<i64>) = conn.query_row(
        "SELECT
           (SELECT COUNT(*) FROM accounts),
           (SELECT COUNT(*) FROM registration_challenges WHERE expires_at>=?1),
           (SELECT COUNT(*) FROM registration_challenges
             WHERE expires_at>=?1 AND verified_at IS NOT NULL),
           (SELECT COUNT(*) FROM registration_challenges WHERE expires_at<?1),
           (SELECT COUNT(*) FROM mail_outbox WHERE state='pending'),
           (SELECT COUNT(*) FROM mail_outbox WHERE state='in_flight'),
           (SELECT COUNT(*) FROM mail_outbox WHERE state='dead'),
           (SELECT MIN(created_at) FROM mail_outbox
             WHERE state IN ('pending','in_flight'))",
        [observed_at],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    let mut database_bytes = 0_u64;
    for path in std::iter::once(database.to_path_buf()).chain(
        ["-wal", "-shm", "-journal"]
            .into_iter()
            .map(|suffix| sqlite_artifact_path(database, suffix)),
    ) {
        match fs::metadata(path) {
            Ok(metadata) => {
                database_bytes = database_bytes.checked_add(metadata.len()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "database size overflow")
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(OperationalSnapshot {
        observed_at,
        schema_version,
        database_bytes,
        accounts,
        registration_challenges_active,
        registration_challenges_verified,
        registration_challenges_expired,
        mail_pending,
        mail_in_flight,
        mail_dead,
        oldest_active_mail_age_seconds: oldest_active_created_at
            .map(|created_at| observed_at.saturating_sub(created_at).max(0)),
    })
}

fn migrate_v0_to_v1(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS accounts(
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
    )?;
    let has_vault_revision = {
        let mut stmt = tx.prepare("PRAGMA table_info(accounts)")?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .any(|column| column == "vault_revision");
        columns
    };
    if !has_vault_revision {
        tx.execute(
            "ALTER TABLE accounts ADD COLUMN vault_revision INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    tx.execute_batch("PRAGMA user_version=1")?;
    tx.commit()
}

fn migrate_v1_to_v2(conn: &mut Connection) -> rusqlite::Result<()> {
    // SQLite cannot change foreign-key declarations in place. Disable
    // enforcement outside the migration transaction, rebuild every related
    // table, validate relationships before commit, then enable it permanently.
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let migration = (|| {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let has_orphans: bool = tx.query_row(
            "SELECT
               EXISTS(SELECT 1 FROM items i LEFT JOIN accounts a ON a.email=i.email
                      WHERE a.email IS NULL)
               OR EXISTS(SELECT 1 FROM manifests m LEFT JOIN accounts a ON a.email=m.email
                         WHERE a.email IS NULL)
               OR EXISTS(SELECT 1 FROM send_directory d LEFT JOIN accounts a ON a.email=d.email
                         WHERE a.email IS NULL)
               OR EXISTS(SELECT 1 FROM send_inbox i LEFT JOIN send_directory d
                         ON d.bastion_id=i.recipient_id WHERE d.bastion_id IS NULL)",
            [],
            |row| row.get(0),
        )?;
        if has_orphans {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute_batch(
            "CREATE TABLE accounts_v2(
               email TEXT PRIMARY KEY, salt TEXT NOT NULL, kdf TEXT NOT NULL,
               wrapped_vault_key TEXT NOT NULL, auth_hash TEXT NOT NULL,
               vault_revision INTEGER NOT NULL DEFAULT 0);
             INSERT INTO accounts_v2 SELECT
               email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision FROM accounts;

             CREATE TABLE items_v2(
               email TEXT NOT NULL, id TEXT NOT NULL, blob TEXT NOT NULL,
               PRIMARY KEY(email, id),
               FOREIGN KEY(email) REFERENCES accounts_v2(email) ON DELETE CASCADE);
             INSERT INTO items_v2 SELECT email,id,blob FROM items;

             CREATE TABLE manifests_v2(
               email TEXT PRIMARY KEY, blob TEXT NOT NULL,
               FOREIGN KEY(email) REFERENCES accounts_v2(email) ON DELETE CASCADE);
             INSERT INTO manifests_v2 SELECT email,blob FROM manifests;

             CREATE TABLE send_directory_v2(
               email TEXT PRIMARY KEY, bastion_id TEXT UNIQUE NOT NULL,
               public TEXT NOT NULL, created_at INTEGER NOT NULL,
               FOREIGN KEY(email) REFERENCES accounts_v2(email) ON DELETE CASCADE);
             INSERT INTO send_directory_v2 SELECT
               email,bastion_id,public,created_at FROM send_directory;

             CREATE TABLE send_inbox_v2(
               recipient_id TEXT NOT NULL, message_id TEXT NOT NULL,
               blob TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER,
               PRIMARY KEY(recipient_id, message_id),
               FOREIGN KEY(recipient_id) REFERENCES send_directory_v2(bastion_id)
                 ON DELETE CASCADE);
             INSERT INTO send_inbox_v2 SELECT
               recipient_id,message_id,blob,created_at,expires_at FROM send_inbox;

             DROP TABLE send_inbox;
             DROP TABLE send_directory;
             DROP TABLE items;
             DROP TABLE manifests;
             DROP TABLE accounts;

             ALTER TABLE accounts_v2 RENAME TO accounts;
             ALTER TABLE items_v2 RENAME TO items;
             ALTER TABLE manifests_v2 RENAME TO manifests;
             ALTER TABLE send_directory_v2 RENAME TO send_directory;
             ALTER TABLE send_inbox_v2 RENAME TO send_inbox;
             CREATE INDEX idx_inbox_recipient ON send_inbox(recipient_id);
             PRAGMA user_version=2;",
        )?;
        tx.commit()
    })();
    let foreign_keys = conn.pragma_update(None, "foreign_keys", "ON");
    migration?;
    foreign_keys
}

fn migrate_v2_to_v3(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE mail_outbox(
           id TEXT PRIMARY KEY,
           account_email TEXT NOT NULL,
           recipient TEXT NOT NULL,
           subject TEXT NOT NULL,
           text_body TEXT NOT NULL,
           state TEXT NOT NULL,
           attempts INTEGER NOT NULL DEFAULT 0,
           available_at INTEGER NOT NULL,
           lease_until INTEGER,
           created_at INTEGER NOT NULL,
           delivered_at INTEGER,
           last_error_code TEXT,
           FOREIGN KEY(account_email) REFERENCES accounts(email) ON DELETE CASCADE,
           CHECK(length(id)=32 AND id=lower(id)),
           CHECK(state IN ('pending','in_flight','delivered','dead')),
           CHECK(attempts BETWEEN 0 AND 8),
           CHECK(available_at>=0 AND created_at>=0),
           CHECK((state='in_flight')=(lease_until IS NOT NULL)),
           CHECK((state='delivered')=(delivered_at IS NOT NULL)),
           CHECK(last_error_code IS NULL OR length(last_error_code)<=64),
           CHECK(
             (state IN ('pending','in_flight')
               AND length(recipient) BETWEEN 1 AND 254
               AND length(subject) BETWEEN 1 AND 160
               AND length(text_body) BETWEEN 1 AND 16384)
             OR
             (state IN ('delivered','dead')
               AND recipient='' AND subject='' AND text_body='')
           ));
         CREATE INDEX idx_mail_outbox_due
           ON mail_outbox(state,available_at,lease_until,created_at);
         PRAGMA user_version=3;",
    )?;
    tx.commit()
}

fn migrate_v3_to_v4(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let migration = (|| {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "ALTER TABLE accounts ADD COLUMN email_verified_at INTEGER;
             UPDATE accounts SET email_verified_at=unixepoch();

             CREATE TABLE registration_challenges(
               email TEXT PRIMARY KEY,
               token_hash BLOB UNIQUE NOT NULL,
               expires_at INTEGER NOT NULL,
               resend_after INTEGER NOT NULL,
               verified_at INTEGER,
               created_at INTEGER NOT NULL,
               CHECK(length(token_hash)=32),
               CHECK(expires_at>=created_at),
               CHECK(resend_after>=created_at),
               CHECK(verified_at IS NULL OR verified_at>=created_at));

             CREATE TABLE mail_outbox_v4(
               id TEXT PRIMARY KEY,
               account_email TEXT,
               challenge_email TEXT,
               recipient TEXT NOT NULL,
               subject TEXT NOT NULL,
               text_body TEXT NOT NULL,
               state TEXT NOT NULL,
               attempts INTEGER NOT NULL DEFAULT 0,
               available_at INTEGER NOT NULL,
               lease_until INTEGER,
               created_at INTEGER NOT NULL,
               delivered_at INTEGER,
               last_error_code TEXT,
               FOREIGN KEY(account_email) REFERENCES accounts(email) ON DELETE CASCADE,
               FOREIGN KEY(challenge_email) REFERENCES registration_challenges(email)
                 ON DELETE CASCADE,
               CHECK((account_email IS NOT NULL)+(challenge_email IS NOT NULL)=1),
               CHECK(length(id)=32 AND id=lower(id)),
               CHECK(state IN ('pending','in_flight','delivered','dead')),
               CHECK(attempts BETWEEN 0 AND 8),
               CHECK(available_at>=0 AND created_at>=0),
               CHECK((state='in_flight')=(lease_until IS NOT NULL)),
               CHECK((state='delivered')=(delivered_at IS NOT NULL)),
               CHECK(last_error_code IS NULL OR length(last_error_code)<=64),
               CHECK(
                 (state IN ('pending','in_flight')
                   AND length(recipient) BETWEEN 1 AND 254
                   AND length(subject) BETWEEN 1 AND 160
                   AND length(text_body) BETWEEN 1 AND 16384)
                 OR
                 (state IN ('delivered','dead')
                   AND recipient='' AND subject='' AND text_body='')
               ));
             INSERT INTO mail_outbox_v4(
               id,account_email,challenge_email,recipient,subject,text_body,state,
               attempts,available_at,lease_until,created_at,delivered_at,last_error_code
             ) SELECT
               id,account_email,NULL,recipient,subject,text_body,state,
               attempts,available_at,lease_until,created_at,delivered_at,last_error_code
             FROM mail_outbox;
             DROP TABLE mail_outbox;
             ALTER TABLE mail_outbox_v4 RENAME TO mail_outbox;
             CREATE INDEX idx_mail_outbox_due
               ON mail_outbox(state,available_at,lease_until,created_at);
             PRAGMA user_version=4;",
        )?;
        tx.commit()
    })();
    let foreign_keys = conn.pragma_update(None, "foreign_keys", "ON");
    migration?;
    foreign_keys
}

fn migrate_schema(conn: &mut Connection) -> rusqlite::Result<()> {
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    assert!(
        version <= CURRENT_SCHEMA_VERSION,
        "database schema version {version} is newer than supported version {CURRENT_SCHEMA_VERSION}"
    );
    while version < CURRENT_SCHEMA_VERSION {
        match version {
            0 => migrate_v0_to_v1(conn)?,
            1 => migrate_v1_to_v2(conn)?,
            2 => migrate_v2_to_v3(conn)?,
            3 => migrate_v3_to_v4(conn)?,
            _ => unreachable!("all schema migrations are explicit"),
        }
        version = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    }
    conn.pragma_update(None, "foreign_keys", "ON")?;
    let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    assert_eq!(foreign_keys, 1, "SQLite foreign keys must remain enabled");
    let has_violation = {
        let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
        let violation = stmt.query([])?.next()?.is_some();
        violation
    };
    if has_violation {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

impl Db {
    fn open(path: &str) -> (Self, HashMap<String, AccountRecord>, [u8; 32]) {
        Self::open_with_limits(path, DB_QUEUE_CAPACITY, DB_RESPONSE_TIMEOUT)
    }

    fn open_with_limits(
        path: &str,
        queue_capacity: usize,
        response_timeout: Duration,
    ) -> (Self, HashMap<String, AccountRecord>, [u8; 32]) {
        let (sender, mut receiver) = mpsc::channel::<DbJob>(queue_capacity);
        let (init_sender, init_receiver) = std::sync::mpsc::sync_channel(1);
        let path = path.to_owned();
        let available = Arc::new(AtomicBool::new(true));
        let worker_available = available.clone();
        let worker = thread::Builder::new()
            .name("bastion-sqlite".to_string())
            .spawn(move || {
                let (mut conn, _instance_lock) = Self::open_connection(&path);
                let accounts = Self::load_accounts_from(&conn).expect("load persisted vault state");
                let decoy_seed =
                    Self::load_or_create_decoy_seed(&conn).expect("load prelogin decoy seed");
                if init_sender.send((accounts, decoy_seed)).is_err() {
                    return;
                }
                while let Some(job) = receiver.blocking_recv() {
                    job(&mut conn);
                }
                worker_available.store(false, Ordering::Release);
                if path != ":memory:" {
                    // Best-effort clean shutdown. A failed checkpoint cannot
                    // invalidate committed WAL transactions, but is surfaced
                    // by readiness/restore checks on the next start.
                    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                }
            })
            .expect("spawn SQLite owner");
        let (accounts, decoy_seed) = match init_receiver.recv() {
            Ok(init) => init,
            Err(_) => {
                let _ = worker.join();
                panic!("SQLite owner failed to initialize");
            }
        };
        (
            Self {
                sender,
                _worker: Arc::new(DbWorker {
                    join: Mutex::new(Some(worker)),
                }),
                available,
                response_timeout,
            },
            accounts,
            decoy_seed,
        )
    }

    /// Loads (or creates on first start) the random per-deployment secret that
    /// keys deterministic prelogin decoys for unknown accounts. Persisted so
    /// decoys stay stable across restarts — an attacker comparing responses
    /// over time learns nothing from a reboot.
    fn load_or_create_decoy_seed(conn: &Connection) -> rusqlite::Result<[u8; 32]> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS server_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL)",
        )?;
        let mut fresh = [0u8; 32];
        OsRng.fill_bytes(&mut fresh);
        conn.execute(
            "INSERT OR IGNORE INTO server_meta(key,value) VALUES('prelogin_decoy_seed',?1)",
            [fresh.as_slice()],
        )?;
        let stored: Vec<u8> = conn.query_row(
            "SELECT value FROM server_meta WHERE key='prelogin_decoy_seed'",
            [],
            |row| row.get(0),
        )?;
        stored
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)
    }

    fn open_connection(path: &str) -> (Connection, Option<File>) {
        let file_path = (path != ":memory:").then(|| FsPath::new(path));
        if let Some(file_path) = file_path {
            prepare_database_path(file_path).expect("secure database path");
        }
        let instance_lock = file_path.map(|file_path| {
            acquire_instance_lock(file_path).expect("acquire exclusive server ownership")
        });
        let mut conn = if path == ":memory:" {
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
            // busy_timeout: a SQLite-aware backup or administrative connection
            // can briefly hold a database lock. Wait a bounded moment instead
            // of surfacing an immediate SQLITE_BUSY as an opaque 500.
            // synchronous=FULL: in WAL mode SQLite syncs the WAL after every
            // commit before acknowledging it. NORMAL preserves consistency but
            // can lose an acknowledged transaction after an OS crash or power
            // loss, which is unacceptable for vault mutations.
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             PRAGMA synchronous=FULL;",
        )
        .expect("configure SQLite");
        migrate_schema(&mut conn).expect("migrate schema");
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .expect("read SQLite synchronous mode");
        assert_eq!(
            synchronous, 2,
            "SQLite must apply synchronous=FULL before the server starts"
        );
        if file_path.is_some() {
            let journal_mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .expect("read SQLite journal mode");
            assert_eq!(
                journal_mode.to_ascii_lowercase(),
                "wal",
                "SQLite must apply journal_mode=WAL before the server starts"
            );
        }
        if let Some(file_path) = file_path {
            secure_database_artifacts(file_path).expect("secure database artifacts");
        }
        (conn, instance_lock)
    }

    async fn call<T, F>(&self, operation: F) -> Result<T, DbError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        self.call_inner(operation, false).await
    }

    async fn call_mutation<T, F>(&self, operation: F) -> Result<T, DbError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        self.call_inner(operation, true).await
    }

    async fn call_inner<T, F>(&self, operation: F, finish_after_timeout: bool) -> Result<T, DbError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        if !self.is_available() {
            return Err(DbError::Quarantined);
        }
        let (result_sender, result_receiver) = oneshot::channel();
        let mut result_receiver = result_receiver;
        let job = Box::new(move |conn: &mut Connection| {
            let _ = result_sender.send(operation(conn).map_err(|_| DbError::Sqlite));
        });
        self.sender.try_send(job).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => DbError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => {
                self.available.store(false, Ordering::Release);
                DbError::WorkerClosed
            }
        })?;
        match tokio::time::timeout(self.response_timeout, &mut result_receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.available.store(false, Ordering::Release);
                Err(DbError::WorkerClosed)
            }
            Err(_) => {
                // The job was accepted and cannot be removed from the worker
                // queue safely. Quarantine the instance immediately. Durable
                // mutations must still finish while their logical cache lock
                // is held, preventing a late commit from diverging the cache.
                self.available.store(false, Ordering::Release);
                if finish_after_timeout {
                    result_receiver.await.map_err(|_| DbError::WorkerClosed)?
                } else {
                    Err(DbError::ResponseTimeout)
                }
            }
        }
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    async fn ready(&self) -> Result<(), DbError> {
        let result = self
            .call(|conn| conn.query_row("SELECT COUNT(*) FROM accounts", [], |_| Ok(())))
            .await;
        if result.is_err() && !matches!(&result, Err(DbError::QueueFull)) {
            // A readiness failure means operators can no longer trust this
            // process to serve its cache consistently with durable state.
            // Recovery is a process restart after the storage fault is fixed.
            self.available.store(false, Ordering::Release);
        }
        result
    }

    async fn mailbox_proof_valid(
        &self,
        email: &str,
        token_hash: [u8; 32],
        now: i64,
    ) -> Result<bool, DbError> {
        let email = email.to_owned();
        self.call(move |conn| {
            conn.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM registration_challenges
                    WHERE email=?1 AND token_hash=?2 AND verified_at IS NOT NULL
                      AND expires_at>=?3
                 )",
                params![email, token_hash.as_slice(), now],
                |row| row.get(0),
            )
        })
        .await
    }

    async fn request_registration_challenge(
        &self,
        mail: RegistrationMail,
    ) -> Result<ChallengeRequestOutcome, DbError> {
        self.call_mutation(move |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM registration_challenges WHERE expires_at<?1",
                [mail.created_at],
            )?;
            let account_exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE email=?1)",
                [&mail.recipient],
                |row| row.get(0),
            )?;
            if account_exists {
                tx.commit()?;
                return Ok(ChallengeRequestOutcome::Noop);
            }
            let resend_after = tx
                .query_row(
                    "SELECT resend_after FROM registration_challenges WHERE email=?1",
                    [&mail.recipient],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if resend_after.is_some_and(|until| mail.created_at < until) {
                tx.commit()?;
                return Ok(ChallengeRequestOutcome::Noop);
            }
            // Replacing the challenge cascades any queued stale message before
            // the new token and mail are inserted atomically.
            tx.execute(
                "DELETE FROM registration_challenges WHERE email=?1",
                [&mail.recipient],
            )?;
            tx.execute(
                "INSERT INTO registration_challenges(
                   email,token_hash,expires_at,resend_after,verified_at,created_at
                 ) VALUES(?1,?2,?3,?4,NULL,?5)",
                params![
                    mail.recipient,
                    mail.token_hash.as_slice(),
                    mail.expires_at,
                    mail.resend_after,
                    mail.created_at
                ],
            )?;
            let queued = mail_outbox::enqueue_registration(
                &tx,
                &mail.recipient,
                mail_outbox::MailDraft {
                    id: &mail.outbox_id,
                    recipient: &mail.recipient,
                    subject: &mail.subject,
                    text_body: &mail.text_body,
                    created_at: mail.created_at,
                },
            )?;
            if !queued {
                return Ok(ChallengeRequestOutcome::QueueFull);
            }
            tx.commit()?;
            Ok(ChallengeRequestOutcome::Queued)
        })
        .await
    }

    async fn verify_registration_challenge(
        &self,
        token_hash: [u8; 32],
        now: i64,
    ) -> Result<Option<String>, DbError> {
        self.call_mutation(move |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let email = tx
                .query_row(
                    "SELECT email FROM registration_challenges
                      WHERE token_hash=?1 AND expires_at>=?2",
                    params![token_hash.as_slice(), now],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(email) = &email {
                tx.execute(
                    "UPDATE registration_challenges
                        SET verified_at=COALESCE(verified_at,?1)
                      WHERE email=?2",
                    params![now, email],
                )?;
            }
            tx.commit()?;
            Ok(email)
        })
        .await
    }

    /// Inserts a new account and consumes an independently verified mailbox
    /// proof in the same transaction. Development callers pass no proof.
    async fn create_account(&self, account: NewAccount) -> Result<AccountCreateOutcome, DbError> {
        self.call_mutation(move |conn| {
            let NewAccount {
                email,
                salt,
                kdf_json,
                wrapped_json,
                auth_hash,
                mailbox_proof,
                created_at,
            } = account;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE email=?1)",
                [&email],
                |row| row.get::<_, bool>(0),
            )? {
                tx.commit()?;
                return Ok(AccountCreateOutcome::Conflict);
            }
            if let Some(token_hash) = mailbox_proof {
                let valid: bool = tx.query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM registration_challenges
                        WHERE email=?1 AND token_hash=?2 AND verified_at IS NOT NULL
                          AND expires_at>=?3
                     )",
                    params![email, token_hash.as_slice(), created_at],
                    |row| row.get(0),
                )?;
                if !valid {
                    tx.commit()?;
                    return Ok(AccountCreateOutcome::InvalidMailboxProof);
                }
            }
            tx.execute(
                "INSERT INTO accounts(
                   email,salt,kdf,wrapped_vault_key,auth_hash,email_verified_at
                 ) VALUES(?1,?2,?3,?4,?5,?6)",
                params![email, salt, kdf_json, wrapped_json, auth_hash, created_at],
            )?;
            if mailbox_proof.is_some() {
                tx.execute(
                    "DELETE FROM registration_challenges WHERE email=?1",
                    [&email],
                )?;
            }
            tx.commit()?;
            Ok(AccountCreateOutcome::Created)
        })
        .await
    }

    /// Delete every server-owned record for an account in one transaction.
    /// Messages already delivered to other recipients cannot be attributed to
    /// or recalled by the zero-knowledge server.
    async fn delete_account(&self, email: &str) -> Result<bool, DbError> {
        let email = email.to_owned();
        self.call_mutation(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "DELETE FROM send_inbox WHERE recipient_id IN (
                   SELECT bastion_id FROM send_directory WHERE email=?1
                 )",
                [&email],
            )?;
            tx.execute("DELETE FROM send_directory WHERE email=?1", [&email])?;
            tx.execute("DELETE FROM items WHERE email=?1", [&email])?;
            tx.execute("DELETE FROM manifests WHERE email=?1", [&email])?;
            let deleted = tx.execute("DELETE FROM accounts WHERE email=?1", [&email])?;
            tx.commit()?;
            Ok(deleted == 1)
        })
        .await
    }

    async fn commit_vault_mutation(
        &self,
        email: &str,
        expected_revision: u64,
        next_revision: u64,
        operations: &[PreparedVaultOperation],
        manifest_json: Option<&str>,
    ) -> Result<DbVaultMutation, DbError> {
        let email = email.to_owned();
        let operations = operations.to_vec();
        let manifest_json = manifest_json.map(str::to_owned);
        self.call_mutation(move |conn| {
            let expected_revision = persisted_revision(expected_revision)?;
            let next_revision = persisted_revision(next_revision)?;
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
        })
        .await
    }

    /// Loads all accounts (with their items and manifest) at startup.
    fn load_accounts_from(
        conn: &Connection,
    ) -> Result<HashMap<String, AccountRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let mut accounts: HashMap<String, AccountRecord> = HashMap::new();

        {
            let mut stmt = conn.prepare(
                "SELECT email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision,email_verified_at
                   FROM accounts",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            })?;
            for row in rows {
                let (email, salt, kdf_s, wrapped_s, auth_hash, vault_revision, email_verified_at) =
                    row?;
                let kdf: KdfParams = serde_json::from_str(&kdf_s)?;
                let wrapped_vault_key: EncryptedBlob = serde_json::from_str(&wrapped_s)?;
                validate_persisted_credentials(&email, &salt, kdf, &wrapped_vault_key, &auth_hash)?;
                let vault_revision = u64::try_from(vault_revision).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "negative vault revision")
                })?;
                if email_verified_at.is_some_and(|verified_at| verified_at < 0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "negative email verification timestamp",
                    )
                    .into());
                }
                accounts.insert(
                    email,
                    AccountRecord {
                        salt,
                        kdf,
                        wrapped_vault_key,
                        auth_hash,
                        email_verified_at,
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
        // Log server-side faults where they funnel. The message is a fixed,
        // non-secret label (no emails/tokens/blobs), so this is safe to emit.
        if self.0.is_server_error() {
            tracing::error!(status = self.0.as_u16(), detail = self.1, "request failed");
        }
        (self.0, self.1).into_response()
    }
}

fn db_api_error(error: DbError) -> ApiError {
    match error {
        DbError::Sqlite => ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"),
        DbError::QueueFull
        | DbError::WorkerClosed
        | DbError::ResponseTimeout
        | DbError::Quarantined => ApiError(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}

// ─── DTO ───

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccount {
    email: String,
    registration: Registration,
    #[serde(default)]
    mailbox_proof: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationChallengeRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRegistrationChallengeRequest {
    token: String,
}

#[derive(Serialize)]
struct VerifyRegistrationChallengeResponse {
    email: String,
}

#[derive(Serialize)]
struct PublicConfig {
    email_verification_required: bool,
}

#[derive(Serialize)]
struct Prelogin {
    salt: String,
    kdf: KdfParams,
    wrapped_vault_key: EncryptedBlob,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    email: String,
    /// Base64 authentication secret derived on the client side.
    auth_secret: AuthSecret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteAccountRequest {
    /// Fresh client-derived proof. A bearer token alone is not deletion authority.
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

#[derive(Serialize)]
struct VaultRevisionResponse {
    revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Process liveness deliberately avoids the storage queue. It must remain
/// responsive while readiness is withdrawn for a busy or failed database.
async fn liveness() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// Database readiness. A wedged, saturated, deleted, or corrupted database
/// must not report ready, or an ingress will continue routing stateful work to
/// an instance that cannot complete it.
async fn readiness(State(st): State<AppState>) -> Response {
    if st.db.ready().await.is_ok() {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response()
    }
}

/// Backward-compatible aggregate health route. Historically this route was a
/// DB readiness check, so preserve those semantics while `/livez` gives
/// operators an independent process signal.
async fn health(state: State<AppState>) -> Response {
    readiness(state).await
}

async fn public_config(State(st): State<AppState>) -> Json<PublicConfig> {
    Json(PublicConfig {
        email_verification_required: st.verification_origin.is_some(),
    })
}

fn verification_token_hash(token: &str) -> Option<[u8; 32]> {
    let mut decoded = [0u8; VERIFICATION_TOKEN_BYTES];
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(token.as_bytes(), &mut decoded)
        .ok()?;
    if decoded_len != VERIFICATION_TOKEN_BYTES || URL_SAFE_NO_PAD.encode(decoded) != token {
        decoded.zeroize();
        return None;
    }
    let hash = Sha256::digest(decoded).into();
    decoded.zeroize();
    Some(hash)
}

fn new_registration_mail(email: &str, origin: &str, now: i64) -> RegistrationMail {
    let mut raw_token = [0u8; VERIFICATION_TOKEN_BYTES];
    OsRng.fill_bytes(&mut raw_token);
    let token = URL_SAFE_NO_PAD.encode(raw_token);
    let token_hash = Sha256::digest(raw_token).into();
    raw_token.zeroize();
    let mut raw_id = [0u8; 16];
    OsRng.fill_bytes(&mut raw_id);
    let outbox_id = data_encoding::HEXLOWER.encode(&raw_id);
    let text_body = format!(
        "Verify this mailbox for a new Bastion vault:\n\n{origin}/verify-email#token={token}\n\nThis link expires in 30 minutes. It proves mailbox control only. It cannot recover your vault, master password, or Secret Key. If you did not request this, ignore this message."
    );
    RegistrationMail {
        outbox_id,
        recipient: email.to_string(),
        subject: "Verify your Bastion mailbox".to_string(),
        text_body,
        token_hash,
        expires_at: now.saturating_add(VERIFICATION_TTL_SECONDS),
        resend_after: now.saturating_add(VERIFICATION_RESEND_SECONDS),
        created_at: now,
    }
}

async fn request_registration_challenge(
    State(st): State<AppState>,
    Json(req): Json<RegistrationChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    let origin = st.verification_origin.as_deref().ok_or(ApiError(
        StatusCode::NOT_FOUND,
        "mailbox verification disabled",
    ))?;
    validate_account_id(&req.email)?;
    if !mail_outbox::valid_recipient(&req.email) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid mailbox"));
    }
    auth_rate_limit(
        &st,
        "global",
        "challenge-global",
        MAX_CHALLENGES_GLOBAL_PER_MIN,
    )
    .await?;
    auth_rate_limit(
        &st,
        &req.email,
        "challenge-email",
        MAX_CHALLENGES_PER_EMAIL_PER_MIN,
    )
    .await?;
    let mail = new_registration_mail(&req.email, origin, now_secs());
    match st
        .db
        .request_registration_challenge(mail)
        .await
        .map_err(db_api_error)?
    {
        ChallengeRequestOutcome::Queued | ChallengeRequestOutcome::Noop => Ok(StatusCode::ACCEPTED),
        ChallengeRequestOutcome::QueueFull => Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "mail queue unavailable",
        )),
    }
}

async fn verify_registration_challenge(
    State(st): State<AppState>,
    Json(mut req): Json<VerifyRegistrationChallengeRequest>,
) -> Result<Json<VerifyRegistrationChallengeResponse>, ApiError> {
    if st.verification_origin.is_none() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "mailbox verification disabled",
        ));
    }
    let token_hash = verification_token_hash(&req.token);
    req.token.zeroize();
    let token_hash = token_hash.ok_or(ApiError(
        StatusCode::BAD_REQUEST,
        "invalid or expired proof",
    ))?;
    auth_rate_limit(
        &st,
        "global",
        "verify-global",
        MAX_VERIFICATIONS_GLOBAL_PER_MIN,
    )
    .await?;
    let rate_key = data_encoding::HEXLOWER.encode(&token_hash[..8]);
    auth_rate_limit(
        &st,
        &rate_key,
        "verify-token",
        MAX_VERIFICATIONS_PER_TOKEN_PER_MIN,
    )
    .await?;
    let email = st
        .db
        .verify_registration_challenge(token_hash, now_secs())
        .await
        .map_err(db_api_error)?
        .ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid or expired proof",
        ))?;
    Ok(Json(VerifyRegistrationChallengeResponse { email }))
}

async fn create_account(
    State(st): State<AppState>,
    Json(mut req): Json<CreateAccount>,
) -> Result<StatusCode, ApiError> {
    validate_account_id(&req.email)?;
    validate_registration(&req.registration)?;
    let now = now_secs();
    let mailbox_proof = if st.verification_origin.is_some() {
        if !mail_outbox::valid_recipient(&req.email) {
            return Err(ApiError(StatusCode::BAD_REQUEST, "invalid mailbox"));
        }
        let mut proof = req
            .mailbox_proof
            .take()
            .ok_or(ApiError(StatusCode::FORBIDDEN, "mailbox proof required"))?;
        let token_hash = verification_token_hash(&proof);
        proof.zeroize();
        let token_hash =
            token_hash.ok_or(ApiError(StatusCode::FORBIDDEN, "mailbox proof required"))?;
        Some(token_hash)
    } else {
        None
    };
    auth_rate_limit(
        &st,
        "global",
        "account-create-global",
        st.auth_rate_limits.account_creations_global,
    )
    .await?;
    auth_rate_limit(
        &st,
        &req.email,
        "account-create-account",
        st.auth_rate_limits.account_creations_per_account,
    )
    .await?;
    // Reject a known duplicate before paying the Argon2 cost. The authoritative
    // collision check is repeated under the write lock after hashing.
    if st.read().await.accounts.contains_key(&req.email) {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    if let Some(token_hash) = mailbox_proof {
        if !st
            .db
            .mailbox_proof_valid(&req.email, token_hash, now)
            .await
            .map_err(db_api_error)?
        {
            return Err(ApiError(StatusCode::FORBIDDEN, "mailbox proof required"));
        }
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
    // clause remains authoritative if the cache and database ever diverge.
    let mut inner = st.write().await;
    if inner.accounts.contains_key(&req.email) {
        return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
    }
    let created = st
        .db
        .create_account(NewAccount {
            email: req.email.clone(),
            salt: req.registration.salt.clone(),
            kdf_json,
            wrapped_json,
            auth_hash: auth_hash.clone(),
            mailbox_proof,
            created_at: now,
        })
        .await
        .map_err(db_api_error)?;
    match created {
        AccountCreateOutcome::Created => {}
        AccountCreateOutcome::Conflict => {
            return Err(ApiError(StatusCode::CONFLICT, "account already exists"));
        }
        AccountCreateOutcome::InvalidMailboxProof => {
            return Err(ApiError(StatusCode::FORBIDDEN, "mailbox proof required"));
        }
    }
    inner.accounts.insert(
        req.email,
        AccountRecord {
            salt: req.registration.salt,
            kdf: req.registration.kdf,
            wrapped_vault_key: req.registration.wrapped_vault_key,
            auth_hash,
            email_verified_at: Some(now),
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

async fn delete_account(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(
        &st,
        &email,
        "account-delete",
        MAX_ACCOUNT_DELETION_ATTEMPTS_PER_MIN,
    )
    .await?;
    if !is_exact_b64(req.auth_secret.expose_b64(), AUTH_SECRET_BYTES) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let phc = st
        .read()
        .await
        .accounts
        .get(&email)
        .map(|account| account.auth_hash.clone())
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let secret = req.auth_secret;
    let permit = auth_permit(&st)?;
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_secret(secret.expose_b64(), &phc)
    })
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "join error"))?;
    if !verified {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }

    // Serialize deletion with every cache-backed account mutation. Database
    // deletion commits before the cache and all account sessions disappear.
    let mut inner = st.write().await;
    if !inner.accounts.contains_key(&email) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let deleted = st.db.delete_account(&email).await.map_err(db_api_error)?;
    if !deleted {
        return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, "db error"));
    }
    inner.accounts.remove(&email);
    inner.sessions.retain(|_, session| session.email != email);
    Ok(StatusCode::NO_CONTENT)
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
    )
    .await?;
    auth_rate_limit(
        &st,
        &email,
        "prelogin-account",
        st.auth_rate_limits.prelogins_per_account,
    )
    .await?;
    let inner = st.read().await;
    // Enumeration resistance: unknown accounts answer with a deterministic
    // decoy shaped exactly like a real registration (same salt length, the
    // registration-default KDF params, a plausible wrapped key). The decoy is
    // keyed by a persisted per-deployment secret, so it is stable across
    // requests and restarts and unpredictable to outsiders. The client's
    // unlock then fails as "invalid master password or Secret Key" — the same
    // failure an existing account gives for wrong credentials.
    match inner.accounts.get(&email) {
        Some(acc) => Ok(Json(Prelogin {
            salt: acc.salt.clone(),
            kdf: acc.kdf,
            wrapped_vault_key: acc.wrapped_vault_key.clone(),
        })),
        None => Ok(Json(prelogin_decoy(&st.prelogin_decoy_seed, &email))),
    }
}

/// Deterministic, secret-keyed decoy prelogin response for unknown accounts.
fn prelogin_decoy(seed: &[u8; 32], email: &str) -> Prelogin {
    // Domain-separated PRF stream: SHA-256(seed || label || 0x00 || email).
    // The secret-prefix construction is safe here (fixed-shape input, no
    // attacker-controlled extension surface across labels).
    let prf = |label: &str, n: usize| -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut counter: u8 = 0;
        while out.len() < n {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(label.as_bytes());
            hasher.update([0u8, counter]);
            hasher.update(email.as_bytes());
            out.extend_from_slice(&hasher.finalize());
            counter = counter.wrapping_add(1);
        }
        out.truncate(n);
        out
    };
    use base64::{engine::general_purpose::STANDARD as B64_STD, Engine as _};
    Prelogin {
        // Same shape as a real registration: 16-byte salt, the registration
        // KDF defaults, and a v1 blob with a 24-byte nonce over a 48-byte
        // ciphertext (32-byte key + 16-byte AEAD tag).
        salt: B64_STD.encode(prf("prelogin-decoy:salt", 16)),
        kdf: KdfParams::default(),
        wrapped_vault_key: EncryptedBlob {
            v: 1,
            nonce: B64_STD.encode(prf("prelogin-decoy:nonce", 24)),
            ct: B64_STD.encode(prf("prelogin-decoy:ct", 48)),
        },
    }
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
    )
    .await?;
    auth_rate_limit(
        &st,
        &req.email,
        "login-account",
        st.auth_rate_limits.login_attempts_per_account,
    )
    .await?;
    // We copy the hash, then release the lock before the slow verification.
    let account = st
        .read()
        .await
        .accounts
        .get(&req.email)
        .map(|a| (a.auth_hash.clone(), a.email_verified_at.is_some()));
    // Same response for "unknown account" and "wrong secret" — and the same
    // Argon2id cost: unknown accounts verify against a process-constant dummy
    // hash so response timing cannot separate the two cases.
    let known = account.is_some();
    let (phc, mailbox_verified) = account.unwrap_or_else(|| (DUMMY_PHC.clone(), false));
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
    if !mailbox_verified {
        return Err(ApiError(StatusCode::FORBIDDEN, "mailbox proof required"));
    }
    let now = Instant::now();
    let expires_at = now + st.token_ttl;
    let mut inner = st.write().await;
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
    let email = require_auth(&st, request.headers()).await?;
    request.extensions_mut().insert(AuthenticatedAccount(email));
    Ok(next.run(request).await)
}

async fn get_vault(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultResponse>, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "vault-read", MAX_VAULT_READS_PER_MIN).await?;
    let inner = st.read().await;
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

/// Cheap authenticated freshness probe. Clients may retain only a snapshot
/// they already verified; any revision change still requires a complete vault
/// fetch and manifest verification before new plaintext is released.
async fn get_vault_revision(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultRevisionResponse>, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(
        &st,
        &email,
        "vault-revision-read",
        MAX_VAULT_REVISION_READS_PER_MIN,
    )
    .await?;
    let inner = st.read().await;
    let revision = inner
        .accounts
        .get(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?
        .vault_revision;
    Ok(Json(VaultRevisionResponse { revision }))
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

    let mut inner = st.write().await;
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
    )
    .await?;

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
    let email = require_auth(&st, &headers).await?;
    let blob_json = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    if blob_json.len() > MAX_VAULT_BLOB_BYTES {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "item too large"));
    }
    // Keep persistence and the read cache in one ordered critical section. If
    // concurrent requests write the same id, the cache winner must be the same
    // request as the SQLite winner.
    let mut inner = st.write().await;
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
    )
    .await?;
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
    let email = require_auth(&st, &headers).await?;
    let mut inner = st.write().await;
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
    )
    .await?;
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
    let email = require_auth(&st, &headers).await?;
    let blob_json = serde_json::to_string(&body.blob)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    if blob_json.len() > MAX_VAULT_MANIFEST_BYTES {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "manifest too large",
        ));
    }
    let mut inner = st.write().await;
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
    )
    .await?;
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

async fn persist_vault_mutation(
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
        .await
        .map_err(db_api_error)?
    {
        DbVaultMutation::Applied => Ok(()),
        // The instance lock excludes other Bastion servers. A DB-only conflict
        // therefore means the cache invariant was violated (for example by a
        // direct administrative write), and this process must fail closed.
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
    st.write().await.sessions.remove(&token);
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
async fn require_auth(st: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = bearer_token(headers)?.to_string();
    let now = Instant::now();
    // Fast path: a valid, unexpired token needs only a READ lock, so concurrent
    // authenticated requests (every GET /vault, /send/inbox…) don't serialize on
    // the global write lock just to be validated.
    {
        let inner = st.read().await;
        match inner.sessions.get(&token) {
            Some(s) if now < s.expires_at => return Ok(s.email.clone()),
            Some(_) => {} // expired → fall through to evict under the write lock
            None => return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token")),
        }
    }
    // Slow path: the token exists but is expired — take the write lock to evict
    // it. Re-check under the lock in case another request already refreshed it.
    let mut inner = st.write().await;
    match inner.sessions.get(&token) {
        Some(s) if now < s.expires_at => Ok(s.email.clone()),
        Some(_) => {
            inner.sessions.remove(&token);
            Err(ApiError(StatusCode::UNAUTHORIZED, "session expired"))
        }
        None => Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token")),
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
async fn rate_limit(st: &AppState, subject: &str, bucket: &str, max: u32) -> Result<(), ApiError> {
    let mut inner = st.write().await;
    rate_limit_map(
        &mut inner.rate,
        st.max_rate_entries,
        st.rate_window,
        subject,
        bucket,
        max,
    )
}

async fn auth_rate_limit(
    st: &AppState,
    subject: &str,
    bucket: &str,
    max: u32,
) -> Result<(), ApiError> {
    let mut inner = st.write().await;
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
    async fn publish_identity(
        &self,
        email: &str,
        public: &PublicIdentity,
        public_json: &str,
    ) -> Result<IdentityPublication, DbError> {
        let email = email.to_owned();
        let public = public.clone();
        let public_json = public_json.to_owned();
        self.call_mutation(move |conn| {
            let existing: Option<(String, String)> = conn
                .query_row(
                    "SELECT bastion_id, public FROM send_directory WHERE email=?1",
                    [&email],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((bastion_id, stored_public)) = existing {
                return Self::classify_existing_identity(bastion_id, &stored_public, &public);
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
                        // Resolve any competing/direct insert as either an
                        // idempotent success or an immutable-identity conflict.
                        let existing: Option<(String, String)> = conn
                            .query_row(
                                "SELECT bastion_id, public FROM send_directory WHERE email=?1",
                                [&email],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            )
                            .optional()?;
                        if let Some((bastion_id, stored_public)) = existing {
                            return Self::classify_existing_identity(
                                bastion_id,
                                &stored_public,
                                &public,
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
        })
        .await
    }

    async fn whoami(&self, email: &str) -> Result<Option<(String, String)>, DbError> {
        let email = email.to_owned();
        self.call(move |conn| {
            conn.query_row(
                "SELECT bastion_id, public FROM send_directory WHERE email=?1",
                [&email],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
        })
        .await
    }

    async fn directory_lookup(&self, bastion_id: &str) -> Result<Option<String>, DbError> {
        let bastion_id = bastion_id.to_owned();
        self.call(move |conn| {
            conn.query_row(
                "SELECT public FROM send_directory WHERE bastion_id=?1",
                [&bastion_id],
                |r| r.get(0),
            )
            .optional()
        })
        .await
    }

    async fn bastion_id_for(&self, email: &str) -> Result<Option<String>, DbError> {
        let email = email.to_owned();
        self.call(move |conn| {
            conn.query_row(
                "SELECT bastion_id FROM send_directory WHERE email=?1",
                [&email],
                |r| r.get(0),
            )
            .optional()
        })
        .await
    }

    /// Atomically enforce the quota and insert (one lock hold → no count/insert
    /// TOCTOU). Dedupe is per-recipient (PK is `(recipient_id, message_id)`).
    async fn insert_inbox(
        &self,
        message_id: &str,
        recipient_id: &str,
        blob: &str,
        expires_at: Option<i64>,
        max: i64,
    ) -> Result<InboxInsert, DbError> {
        let message_id = message_id.to_owned();
        let recipient_id = recipient_id.to_owned();
        let blob = blob.to_owned();
        self.call_mutation(move |conn| {
            let recipient_exists = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM send_directory WHERE bastion_id=?1)",
                [&recipient_id],
                |row| row.get::<_, bool>(0),
            )?;
            if !recipient_exists {
                return Ok(InboxInsert::UnknownRecipient);
            }
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM send_inbox WHERE recipient_id=?1",
                [&recipient_id],
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
        })
        .await
    }

    async fn purge_expired(&self, recipient_id: &str, now: i64) -> Result<(), DbError> {
        let recipient_id = recipient_id.to_owned();
        self.call_mutation(move |conn| {
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
        })
        .await
    }

    async fn inbox_list(&self, recipient_id: &str, now: i64) -> Result<Vec<InboxItem>, DbError> {
        let recipient_id = recipient_id.to_owned();
        self.call(move |conn| {
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
                blob.validate_stored_routing(&message_id, &recipient_id)
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
        })
        .await
    }

    /// Delete a message only if it belongs to `recipient_id` (read-once).
    async fn inbox_delete(&self, message_id: &str, recipient_id: &str) -> Result<usize, DbError> {
        let message_id = message_id.to_owned();
        let recipient_id = recipient_id.to_owned();
        self.call_mutation(move |conn| {
            conn.execute(
                "DELETE FROM send_inbox WHERE message_id=?1 AND recipient_id=?2",
                params![message_id, recipient_id],
            )
        })
        .await
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
#[serde(deny_unknown_fields)]
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
    UnknownRecipient,
}

/// Publish the caller's validated Send public identity. Identical retries are
/// idempotent; key changes require a separate proof-authorized protocol.
async fn publish_identity(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(public): Json<PublicIdentity>,
) -> Result<Json<PublishResponse>, ApiError> {
    let email = require_auth(&st, &headers).await?;
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
    // Serialize publication with account deletion. A request authenticated just
    // before deletion must not recreate an orphaned directory entry afterward.
    let inner = st.write().await;
    if !inner.accounts.contains_key(&email) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    let publication = st
        .db
        .publish_identity(&email, &public, &public_json)
        .await
        .map_err(db_api_error)?;
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
    let email = require_auth(&st, &headers).await?;
    match st.db.whoami(&email).await.map_err(db_api_error)? {
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
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "lookup", MAX_LOOKUPS_PER_MIN).await?;
    if !valid_bastion_id(&bastion_id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad bastion id"));
    }
    match st
        .db
        .directory_lookup(&bastion_id)
        .await
        .map_err(db_api_error)?
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
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "send", MAX_SENDS_PER_MIN).await?;

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
        .await
        .map_err(db_api_error)?
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
    rate_limit(&st, &body.recipient_id, "inbound", MAX_INBOUND_PER_MIN).await?;
    st.db
        .purge_expired(&body.recipient_id, now)
        .await
        .map_err(db_api_error)?;
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
        .await
        .map_err(db_api_error)?
    {
        InboxInsert::Inserted => Ok(StatusCode::NO_CONTENT),
        InboxInsert::Duplicate => Err(ApiError(StatusCode::CONFLICT, "duplicate message")),
        InboxInsert::Full => Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "recipient inbox full",
        )),
        InboxInsert::UnknownRecipient => Err(ApiError(StatusCode::NOT_FOUND, "unknown recipient")),
    }
}

/// Pull the caller's inbox (blobs addressed to their Bastion ID).
async fn send_inbox(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InboxItem>>, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "inbox-read", MAX_INBOX_READS_PER_MIN).await?;
    let mine = st
        .db
        .bastion_id_for(&email)
        .await
        .map_err(db_api_error)?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no identity published"))?;
    let now = now_secs();
    st.db
        .purge_expired(&mine, now)
        .await
        .map_err(db_api_error)?;
    let items = st.db.inbox_list(&mine, now).await.map_err(db_api_error)?;
    Ok(Json(items))
}

/// Delete a message from the caller's inbox (read-once / after processing).
async fn send_inbox_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers).await?;
    if !valid_message_id(&message_id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad message id"));
    }
    let mine = st
        .db
        .bastion_id_for(&email)
        .await
        .map_err(db_api_error)?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no identity published"))?;
    st.db
        .inbox_delete(&message_id, &mine)
        .await
        .map_err(db_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    fn config_from(values: &[(&str, &str)]) -> Result<ServerConfig, String> {
        ServerConfig::from_lookup(|name| {
            values
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
        })
    }

    #[test]
    fn production_config_is_explicit_and_fail_closed() {
        let valid = [
            ("BASTION_ENV", "production"),
            ("BIND_ADDR", "127.0.0.1:7777"),
            ("BASTION_DB", "/var/lib/bastion/bastion.db"),
            ("BASTION_PUBLIC_ORIGIN", "https://vault.example.com"),
            ("BASTION_SMTP_HOST", "smtp.example.com"),
            ("BASTION_SMTP_PORT", "587"),
            ("BASTION_SMTP_USERNAME", "bastion"),
            ("BASTION_SMTP_PASSWORD", "secret"),
            ("BASTION_MAIL_FROM", "no-reply@example.com"),
        ];
        let config = config_from(&valid).unwrap();
        assert!(config.is_production());
        assert_eq!(config.bind_addr(), "127.0.0.1:7777".parse().unwrap());
        assert_eq!(config.db_path(), "/var/lib/bastion/bastion.db");
        assert_eq!(config.public_origin(), Some("https://vault.example.com"));

        for (name, values) in [
            ("unknown mode", vec![("BASTION_ENV", "prod")]),
            (
                "public bind",
                vec![
                    ("BASTION_ENV", "production"),
                    ("BIND_ADDR", "0.0.0.0:7777"),
                    ("BASTION_DB", "/var/lib/bastion/bastion.db"),
                    ("BASTION_PUBLIC_ORIGIN", "https://vault.example.com"),
                ],
            ),
            (
                "relative database",
                vec![
                    ("BASTION_ENV", "production"),
                    ("BIND_ADDR", "127.0.0.1:7777"),
                    ("BASTION_DB", "bastion.db"),
                    ("BASTION_PUBLIC_ORIGIN", "https://vault.example.com"),
                ],
            ),
            (
                "plaintext origin",
                vec![
                    ("BASTION_ENV", "production"),
                    ("BIND_ADDR", "127.0.0.1:7777"),
                    ("BASTION_DB", "/var/lib/bastion/bastion.db"),
                    ("BASTION_PUBLIC_ORIGIN", "http://vault.example.com"),
                ],
            ),
            (
                "origin path",
                vec![
                    ("BASTION_ENV", "production"),
                    ("BIND_ADDR", "127.0.0.1:7777"),
                    ("BASTION_DB", "/var/lib/bastion/bastion.db"),
                    ("BASTION_PUBLIC_ORIGIN", "https://vault.example.com/api"),
                ],
            ),
            (
                "explicit default port",
                vec![
                    ("BASTION_ENV", "production"),
                    ("BIND_ADDR", "127.0.0.1:7777"),
                    ("BASTION_DB", "/var/lib/bastion/bastion.db"),
                    ("BASTION_PUBLIC_ORIGIN", "https://vault.example.com:443"),
                ],
            ),
        ] {
            assert!(config_from(&values).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn development_config_keeps_safe_local_defaults() {
        let config = config_from(&[]).unwrap();
        assert!(!config.is_production());
        assert_eq!(config.bind_addr(), "127.0.0.1:7777".parse().unwrap());
        assert_eq!(config.db_path(), "bastion.db");
        assert_eq!(config.public_origin(), None);
    }

    #[test]
    fn smtp_configuration_is_complete_and_starttls_only() {
        let configured = config_from(&[
            ("BASTION_SMTP_HOST", "smtp.example.com"),
            ("BASTION_SMTP_PORT", "587"),
            ("BASTION_SMTP_USERNAME", "bastion"),
            ("BASTION_SMTP_PASSWORD", "not-logged"),
            ("BASTION_MAIL_FROM", "Bastion <no-reply@example.com>"),
        ])
        .unwrap();
        assert!(configured.smtp.is_some());

        for partial in [
            vec![("BASTION_SMTP_HOST", "smtp.example.com")],
            vec![
                ("BASTION_SMTP_HOST", "smtp.example.com"),
                ("BASTION_SMTP_PORT", "0"),
                ("BASTION_SMTP_USERNAME", "bastion"),
                ("BASTION_SMTP_PASSWORD", "secret"),
                ("BASTION_MAIL_FROM", "no-reply@example.com"),
            ],
            vec![
                ("BASTION_SMTP_HOST", "smtp example.com"),
                ("BASTION_SMTP_PORT", "587"),
                ("BASTION_SMTP_USERNAME", "bastion"),
                ("BASTION_SMTP_PASSWORD", "secret"),
                ("BASTION_MAIL_FROM", "no-reply@example.com"),
            ],
        ] {
            assert!(config_from(&partial).is_err());
        }

        assert!(config_from(&[
            ("BASTION_ENV", "production"),
            ("BIND_ADDR", "127.0.0.1:7777"),
            ("BASTION_DB", "/var/lib/bastion/bastion.db"),
            ("BASTION_PUBLIC_ORIGIN", "https://vault.example.com"),
        ])
        .is_err());
    }

    fn registration_mail(email: &str, token: [u8; 32], now: i64) -> RegistrationMail {
        RegistrationMail {
            outbox_id: data_encoding::HEXLOWER.encode(&[9u8; 16]),
            recipient: email.to_string(),
            subject: "Verify your Bastion mailbox".to_string(),
            text_body: "bounded verification body".to_string(),
            token_hash: Sha256::digest(token).into(),
            expires_at: now + VERIFICATION_TTL_SECONDS,
            resend_after: now + VERIFICATION_RESEND_SECONDS,
            created_at: now,
        }
    }

    #[tokio::test]
    async fn mailbox_proof_is_rotated_then_consumed_with_account_creation() {
        let (db, _, _) = Db::open(":memory:");
        let email = "proof@example.com";
        let first = [1u8; 32];
        let second = [2u8; 32];
        assert!(matches!(
            db.request_registration_challenge(registration_mail(email, first, 100))
                .await
                .unwrap(),
            ChallengeRequestOutcome::Queued
        ));
        // A resend inside the durable cooldown is a generic no-op.
        assert!(matches!(
            db.request_registration_challenge(registration_mail(email, second, 150))
                .await
                .unwrap(),
            ChallengeRequestOutcome::Noop
        ));
        // After the cooldown, replacement invalidates the first proof and its
        // queued message through the challenge foreign key.
        assert!(matches!(
            db.request_registration_challenge(registration_mail(email, second, 220))
                .await
                .unwrap(),
            ChallengeRequestOutcome::Queued
        ));
        assert!(db
            .verify_registration_challenge(Sha256::digest(first).into(), 220)
            .await
            .unwrap()
            .is_none());
        let second_hash: [u8; 32] = Sha256::digest(second).into();
        assert!(matches!(
            db.create_account(NewAccount {
                email: email.to_string(),
                salt: "salt".to_string(),
                kdf_json: "{}".to_string(),
                wrapped_json: "{}".to_string(),
                auth_hash: "hash".to_string(),
                mailbox_proof: Some(second_hash),
                created_at: 220,
            })
            .await
            .unwrap(),
            AccountCreateOutcome::InvalidMailboxProof
        ));
        assert_eq!(
            db.verify_registration_challenge(second_hash, 220)
                .await
                .unwrap()
                .as_deref(),
            Some(email)
        );
        assert!(db
            .mailbox_proof_valid(email, second_hash, 220)
            .await
            .unwrap());

        assert!(matches!(
            db.create_account(NewAccount {
                email: email.to_string(),
                salt: "salt".to_string(),
                kdf_json: "{}".to_string(),
                wrapped_json: "{}".to_string(),
                auth_hash: "hash".to_string(),
                mailbox_proof: Some(second_hash),
                created_at: 220,
            })
            .await
            .unwrap(),
            AccountCreateOutcome::Created
        ));
        assert!(!db
            .mailbox_proof_valid(email, second_hash, 220)
            .await
            .unwrap());
        let (verified_at, challenges, queued): (Option<i64>, i64, i64) = db
            .call(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT email_verified_at FROM accounts WHERE email=?1",
                        [email],
                        |row| row.get(0),
                    )?,
                    conn.query_row("SELECT COUNT(*) FROM registration_challenges", [], |row| {
                        row.get(0)
                    })?,
                    conn.query_row("SELECT COUNT(*) FROM mail_outbox", [], |row| row.get(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(verified_at, Some(220));
        assert_eq!(challenges, 0);
        assert_eq!(queued, 0);
    }

    #[tokio::test]
    async fn production_boundary_requires_exact_ingress_contract() {
        let app = build_with_transport(
            DEFAULT_TOKEN_TTL,
            ":memory:",
            MAX_CONCURRENT_AUTH,
            Some(TransportPolicy::parse("https://vault.example.com").unwrap()),
            None,
        );

        for (name, host, proto, expected) in [
            (
                "missing host",
                None,
                Some("https"),
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "wrong host",
                Some("attacker.example"),
                Some("https"),
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "wrong port",
                Some("vault.example.com:444"),
                Some("https"),
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "missing proto",
                Some("vault.example.com"),
                None,
                StatusCode::BAD_REQUEST,
            ),
            (
                "plaintext proto",
                Some("vault.example.com"),
                Some("http"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "forwarded list",
                Some("vault.example.com"),
                Some("https,http"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "valid ingress",
                Some("VAULT.EXAMPLE.COM"),
                Some("https"),
                // Unknown accounts now answer 200 with an enumeration decoy.
                StatusCode::OK,
            ),
        ] {
            let mut request = Request::builder().uri("/v1/accounts/nobody@example.com/prelogin");
            if let Some(host) = host {
                request = request.header(header::HOST, host);
            }
            if let Some(proto) = proto {
                request = request.header(FORWARDED_PROTO_HEADER, proto);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{name}");
            assert_eq!(
                response.headers()[header::STRICT_TRANSPORT_SECURITY],
                "max-age=31536000",
                "{name}"
            );
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none(),
                "CORS opened for {name}"
            );
        }

        for duplicate in [header::HOST.as_str(), FORWARDED_PROTO_HEADER] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/accounts/nobody@example.com/prelogin")
                        .header(header::HOST, "vault.example.com")
                        .header(FORWARDED_PROTO_HEADER, "https")
                        .header(duplicate, "https")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "accepted duplicate {duplicate}"
            );
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connection_pragmas_are_hardened() {
        let (db, _, _) = Db::open(":memory:");
        let (busy_timeout, synchronous, foreign_keys, user_version) = db
            .call(|conn| {
                Ok((
                    conn.query_row("PRAGMA busy_timeout", [], |r| r.get::<_, i64>(0))?,
                    conn.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))?,
                    conn.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))?,
                    conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(busy_timeout, 5000);
        // 2 = FULL. In WAL mode this syncs every commit before acknowledgement.
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);
        assert_eq!(user_version, CURRENT_SCHEMA_VERSION);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_sqlite_does_not_block_tokio_and_queue_saturation_fails_fast() {
        let (db, _, _) = Db::open_with_limits(":memory:", 1, Duration::from_secs(1));
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);

        let blocked_db = db.clone();
        let blocked = tokio::spawn(async move {
            blocked_db
                .call(move |_| {
                    entered_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    Ok(())
                })
                .await
        });
        tokio::task::spawn_blocking(move || {
            entered_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        })
        .await
        .unwrap();

        // A current-thread timer and liveness response still progress while the
        // SQLite owner is deliberately blocked on another OS thread.
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(liveness().await.status(), StatusCode::OK);
        })
        .await
        .unwrap();

        let queued_db = db.clone();
        let queued = tokio::spawn(async move { queued_db.call(|_| Ok(())).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while db.sender.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(db.call(|_| Ok(())).await, Err(DbError::QueueFull)));

        release_sender.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delayed_accepted_mutation_finishes_then_quarantines_the_instance() {
        let (db, _, _) = Db::open_with_limits(":memory:", 1, Duration::from_millis(10));
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = completed.clone();

        db.call_mutation(move |conn| {
            thread::sleep(Duration::from_millis(50));
            conn.execute("CREATE TABLE delayed(value INTEGER)", [])?;
            worker_completed.store(true, Ordering::Release);
            Ok(())
        })
        .await
        .unwrap();

        assert!(completed.load(Ordering::Acquire));
        assert!(!db.is_available());
        assert!(matches!(db.ready().await, Err(DbError::Quarantined)));
    }

    #[test]
    fn request_log_path_is_redacted_of_user_data() {
        // Emails and opaque ids must never reach the logs.
        assert_eq!(
            redacted_path("/accounts/alice%40example.com/prelogin"),
            "/accounts/{email}/prelogin"
        );
        assert_eq!(
            redacted_path("/v1/accounts/alice%40example.com/prelogin"),
            "/v1/accounts/{email}/prelogin"
        );
        assert_eq!(
            redacted_path("/send/directory/ABCDEF"),
            "/send/directory/{id}"
        );
        assert_eq!(redacted_path("/send/inbox/msg-123"), "/send/inbox/{id}");
        assert_eq!(redacted_path("/vault/items/item-9"), "/vault/items/{id}");
        // Fixed routes pass through unchanged.
        assert_eq!(redacted_path("/vault"), "/vault");
        assert_eq!(redacted_path("/health"), "/health");
        assert_eq!(redacted_path("/livez"), "/livez");
        assert_eq!(redacted_path("/readyz"), "/readyz");
        assert_eq!(redacted_path("/send/inbox"), "/send/inbox");
    }
}

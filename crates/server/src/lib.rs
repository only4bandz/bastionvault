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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{
    mpsc, oneshot, OwnedSemaphorePermit, RwLock, RwLockReadGuard, RwLockWriteGuard, Semaphore,
};
use zeroize::{Zeroize, Zeroizing};

use crypto_core::{AuthSecret, EncryptedBlob, KdfParams, PublicIdentity, Registration, SendBlob};

/// Default session token lifetime (30 min).
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// A rotated access token may renew the 30-minute access window, but never
/// extend one authenticated session beyond this process-local absolute cap.
const DEFAULT_SESSION_ABSOLUTE_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// Already-dispatched requests may still carry the predecessor after rotation.
/// One minute covers the client's 15-second deadline plus its idempotent retry
/// without leaving a useful long-lived second bearer token.
const DEFAULT_SESSION_ROTATION_GRACE: Duration = Duration::from_secs(60);
/// Maximum request body size (1 MiB) — guardrail against memory DoS.
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_SESSION_BODY_BYTES: usize = 1024;
/// Account and registration-challenge payloads are structurally tiny (an
/// email, a fixed-size registration envelope, or a challenge token), yet they
/// are reachable without credentials. Bounding them tightly keeps anonymous
/// callers from making the server buffer and parse the global 1 MiB limit.
const MAX_ACCOUNT_BODY_BYTES: usize = 4 * 1024;
const MAX_ACCOUNT_ID_BYTES: usize = 254;
const AUTH_SECRET_BYTES: usize = 32;
const SESSION_TOKEN_BYTES: usize = 32;
const SESSION_TOKEN_HEX_CHARS: usize = SESSION_TOKEN_BYTES * 2;
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
/// How often expired sessions are reclaimed. Expiry is enforced per token on
/// every request, so this interval bounds memory, never access.
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const MAX_AUTH_RATE_ENTRIES: usize = 10_000;
/// Source buckets are keyed by caller-chosen addresses, so they get their own
/// table and their own bound.
const MAX_SOURCE_RATE_ENTRIES: usize = 20_000;
const MAX_ACCOUNT_CREATIONS_GLOBAL_PER_MIN: u32 = 20;
const MAX_ACCOUNT_CREATIONS_PER_SOURCE_PER_MIN: u32 = 5;
const MAX_ACCOUNT_CREATIONS_PER_ACCOUNT_PER_MIN: u32 = 2;
const MAX_LOGIN_ATTEMPTS_GLOBAL_PER_MIN: u32 = 120;
const MAX_LOGIN_ATTEMPTS_PER_SOURCE_PER_MIN: u32 = 30;
const MAX_LOGIN_ATTEMPTS_PER_ACCOUNT_PER_MIN: u32 = 10;
// Prelogin is unauthenticated and reveals whether an account exists (plus its
// KDF params), so it gets its own throttle against bulk enumeration.
const MAX_PRELOGINS_GLOBAL_PER_MIN: u32 = 300;
const MAX_PRELOGINS_PER_SOURCE_PER_MIN: u32 = 60;
const MAX_PRELOGINS_PER_ACCOUNT_PER_MIN: u32 = 15;
/// Bastion Send: max stored blob size, per-recipient inbox cap, and per-account
/// token-bucket rate limits (abuse controls — see docs/bastion-send-design.md §8).
const MAX_SEND_BLOB: usize = 256 * 1024;
const MAX_SEND_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_INBOX: i64 = 500;
const MAX_INBOX_PAGE: i64 = 100; // cap a single inbox fetch (paginate by deleting)
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_SENDS_PER_MIN: u32 = 60; // per sender
const MAX_INBOUND_PER_MIN: u32 = 120; // per recipient (anti inbox-flood)
const MAX_INBOUND_PER_SENDER_RECIPIENT_PER_MIN: u32 = 30;
/// Standing share of a recipient's inbox any one sender may consume.
///
/// The per-minute pair limit only slows a flood: at 30 a minute one account
/// fills a 500-message inbox in under twenty minutes, after which every other
/// sender is refused until the recipient deletes messages. A long-window pair
/// limit bounds how much of that capacity a single sender can hold at once,
/// leaving the rest of the inbox reachable by everyone else.
///
/// A strict occupancy quota — "this sender currently holds N of your 500" —
/// is deliberately not implemented: it would require storing which account
/// sent each stored message, turning the inbox table into a durable
/// sender/recipient social graph. See docs/bastion-send-design.md §7.
const MAX_INBOUND_PER_SENDER_RECIPIENT_PER_DAY: u32 = 150;
const INBOUND_PAIR_DAY: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_LOOKUPS_PER_MIN: u32 = 120;
const MAX_IDENTITY_PUBLICATIONS_PER_MIN: u32 = 10;
const MAX_WHOAMI_READS_PER_MIN: u32 = 120;
// Authenticated read throttles: a full vault read clones and re-serializes up
// to MAX_VAULT_BYTES per call, and an inbox read runs a purge + list — both
// are cheap amplification levers for a hostile-but-authenticated client.
const MAX_VAULT_READS_PER_MIN: u32 = 60;
const MAX_VAULT_REVISION_READS_PER_MIN: u32 = 300;
const MAX_VAULT_MUTATIONS_PER_MIN: u32 = 120;
/// SQLite has one owner and vault transactions hold the cache write lock until
/// their durable commit is known. Admit only one such transaction at a time so
/// a hostile account cannot pre-load a long queue behind a slow commit.
const MAX_CONCURRENT_VAULT_TRANSACTIONS: usize = 1;
/// How long a vault transaction waits for that slot before giving up. The slot
/// is global, so rejecting immediately turned one account's in-flight commit
/// into a failed write for every other account; a short wait lets ordinary
/// concurrency queue instead of fail.
const VAULT_TRANSACTION_ADMISSION_WAIT: Duration = Duration::from_secs(2);
/// Ceiling on requests waiting for that slot. Waiting must not become its own
/// unbounded queue.
const MAX_WAITING_VAULT_TRANSACTIONS: usize = 64;
const MAX_INBOX_READS_PER_MIN: u32 = 60;
const MAX_INBOX_DELETES_PER_MIN: u32 = 120;
const MAX_ACCOUNT_DELETION_ATTEMPTS_PER_MIN: u32 = 5;
const MAX_RATE_ENTRIES: usize = 100_000; // bound the in-memory rate map (anti memory-DoS)
/// Maximum accepted SQLite commands waiting behind the dedicated connection
/// owner. Saturation fails fast instead of allocating unbounded work.
const DB_QUEUE_CAPACITY: usize = 256;
/// Upper bound for an accepted storage command to produce a response. SQLite's
/// own busy timeout is shorter, leaving headroom for queueing and validation.
const DB_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Readiness answers from a short-lived cache. The probe is unauthenticated, so
/// without this every scrape (or flood) enqueues its own storage command and an
/// outsider can saturate the single SQLite owner for free.
const READINESS_CACHE_TTL: Duration = Duration::from_millis(500);
/// Latest schema understood by this binary. Startup refuses newer databases
/// instead of silently running code against an incompatible layout.
const CURRENT_SCHEMA_VERSION: i64 = 5;
const VERIFICATION_TOKEN_BYTES: usize = 32;
const VERIFICATION_TTL_SECONDS: i64 = 30 * 60;
const VERIFICATION_RESEND_SECONDS: i64 = 2 * 60;
const MAX_CHALLENGES_GLOBAL_PER_MIN: u32 = 30;
const MAX_CHALLENGES_PER_SOURCE_PER_MIN: u32 = 10;
/// Logout is deliberately cheap and always answers 204, so it needs admission
/// of its own: it is the only endpoint where a caller with no valid
/// credential could otherwise reach the global write lock at will.
const MAX_LOGOUTS_PER_SOURCE_PER_MIN: u32 = 60;
const MAX_CHALLENGES_PER_EMAIL_PER_MIN: u32 = 2;
/// Standing daily allowance of verification mail per recipient mailbox. The
/// per-minute bucket only bounds bursts, so an attacker rotating source
/// addresses could otherwise direct one email at an arbitrary third-party
/// mailbox every resend interval indefinitely, spending this deployment's
/// SMTP reputation. Ten per day covers every legitimate retry pattern.
const MAX_CHALLENGES_PER_EMAIL_PER_DAY: u32 = 10;
const CHALLENGE_EMAIL_DAY: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_VERIFICATIONS_GLOBAL_PER_MIN: u32 = 120;
const MAX_VERIFICATIONS_PER_SOURCE_PER_MIN: u32 = 30;
const MAX_VERIFICATIONS_PER_TOKEN_PER_MIN: u32 = 5;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7777";
const DEFAULT_DB_PATH: &str = "bastion.db";
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";

/// Validated process configuration. Production is deliberately narrower than
/// development: a same-host TLS ingress is public and Axum stays on loopback.
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
pub fn app_with_config(config: ServerConfig) -> Router {
    let ServerConfig {
        db_path,
        transport,
        smtp,
        ..
    } = config;
    build_with_transport(
        DEFAULT_TOKEN_TTL,
        &db_path,
        MAX_CONCURRENT_AUTH,
        transport,
        smtp,
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

/// Test-only topology combining mailbox proof with custom authentication
/// rate limits, so standing allowances can be exercised without waiting out
/// the per-minute buckets.
#[doc(hidden)]
pub fn app_with_db_mailbox_verification_and_auth_rate_limits(
    db_path: &str,
    origin: &str,
    limits: AuthRateLimits,
) -> Router {
    build_with_rate_limits(
        DEFAULT_TOKEN_TTL,
        db_path,
        MAX_CONCURRENT_AUTH,
        RuntimeOptions {
            verification_origin: Some(origin.to_string()),
            auth_rate_limits: limits,
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

/// In-memory variant with explicit access, absolute, and rotation-grace
/// lifetimes for deterministic session lifecycle tests.
#[doc(hidden)]
pub fn app_in_memory_with_session_lifetimes(
    token_ttl: Duration,
    absolute_ttl: Duration,
    rotation_grace: Duration,
) -> Router {
    build_with_rate_limits(
        token_ttl,
        ":memory:",
        MAX_CONCURRENT_AUTH,
        RuntimeOptions {
            session_absolute_ttl: absolute_ttl,
            session_rotation_grace: rotation_grace,
            ..RuntimeOptions::default()
        },
    )
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
    max_source_rate_entries: usize,
    rate_window: Duration,
    auth_rate_limits: AuthRateLimits,
    transport: Option<TransportPolicy>,
    smtp: Option<mail_outbox::SmtpConfig>,
    verification_origin: Option<String>,
    session_absolute_ttl: Duration,
    session_rotation_grace: Duration,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            max_rate_entries: MAX_RATE_ENTRIES,
            max_source_rate_entries: MAX_SOURCE_RATE_ENTRIES,
            rate_window: RATE_WINDOW,
            auth_rate_limits: AuthRateLimits::default(),
            transport: None,
            smtp: None,
            verification_origin: None,
            session_absolute_ttl: DEFAULT_SESSION_ABSOLUTE_TTL,
            session_rotation_grace: DEFAULT_SESSION_ROTATION_GRACE,
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
    // The compatibility routes mutate ciphertext and its manifest separately.
    // Keep them available to development clients, but do not expose a
    // non-atomic vault write path once the production transport contract is on.
    let allow_deprecated_vault_mutations = options.transport.is_none();
    let state = AppState::new(token_ttl, db_path, auth_limit, options);
    let transaction_route = put(apply_vault_transaction)
        .layer(DefaultBodyLimit::max(MAX_VAULT_TRANSACTION_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_vault_transaction,
        ));
    let protected_routes = Router::new()
        .route(
            "/accounts",
            post(create_account)
                .delete(delete_account)
                .layer(DefaultBodyLimit::max(MAX_ACCOUNT_BODY_BYTES)),
        )
        .route("/accounts/:email/prelogin", get(prelogin))
        .route(
            "/registration-challenges",
            post(request_registration_challenge)
                .layer(DefaultBodyLimit::max(MAX_ACCOUNT_BODY_BYTES)),
        )
        .route(
            "/registration-challenges/verify",
            post(verify_registration_challenge)
                .layer(DefaultBodyLimit::max(MAX_ACCOUNT_BODY_BYTES)),
        )
        .route(
            "/sessions",
            post(create_session)
                .put(rotate_session)
                .delete(delete_session)
                .layer(DefaultBodyLimit::max(MAX_SESSION_BODY_BYTES)),
        )
        .route("/sessions/all", axum::routing::delete(delete_all_sessions))
        .route("/vault", get(get_vault))
        .route("/vault/revision", get(get_vault_revision))
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
    let protected_routes = if allow_deprecated_vault_mutations {
        protected_routes
            .route("/vault/items/:id", put(put_item).delete(delete_item))
            .route("/vault/manifest", put(put_manifest))
    } else {
        protected_routes
    };
    let mut routes = Router::new()
        .route("/config", get(public_config))
        .route("/health", get(health))
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .route("/.well-known/security.txt", get(security_txt))
        .merge(protected_routes);
    // Registered last and only on paths no client uses, so a lure can never
    // shadow a real route: `Router::route` panics on a duplicate path, which
    // makes that a build-time guarantee rather than a review promise.
    for path in HONEYPOT_PATHS {
        routes = routes.route(path, get(honeypot).post(honeypot));
    }
    let routes = routes;
    let legacy = routes
        .clone()
        .layer(middleware::from_fn(legacy_api_headers));
    Router::new()
        .merge(legacy)
        .nest("/v1", routes)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        // Outside the handlers (and the body extractors that run inside
        // them), so the deadline covers slow body trickle as well as slow
        // handler work. Inside `security_headers`/`request_log`, so a 408 is
        // still stamped and logged like any other response.
        .layer(middleware::from_fn(request_deadline))
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
    if !st.db.is_accepting_work() {
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
/// Redacts dynamic route segments and collapses every unmatched path, so the
/// request log never records an email, opaque id, accidental token, or
/// attacker-controlled high-cardinality 404 path.
fn redacted_path(path: &str) -> String {
    if path.starts_with("/v1/") {
        let versioned = path.strip_prefix("/v1").expect("checked prefix");
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
    // A honeypot path is a fixed, closed set chosen by us, so keeping it
    // verbatim adds no attacker-controlled cardinality and tells an operator
    // which lure was tripped.
    if is_honeypot_path(path) {
        return path.to_string();
    }
    if matches!(
        path,
        "/config"
            | "/.well-known/security.txt"
            | "/health"
            | "/livez"
            | "/readyz"
            | "/accounts"
            | "/registration-challenges"
            | "/registration-challenges/verify"
            | "/sessions"
            | "/sessions/all"
            | "/vault"
            | "/vault/revision"
            | "/vault/manifest"
            | "/vault/transaction"
            | "/send/identity"
            | "/send/whoami"
            | "/send"
            | "/send/inbox"
    ) {
        return path.to_string();
    }
    "/{unmatched}".to_string()
}

/// Process-lifetime tallies of security-relevant outcomes.
///
/// Each event carries its running total, so a log pipeline can alert on the
/// rate of `security` lines without a metrics endpoint to expose or protect.
/// One counter per class: no per-account, per-token or per-IP state, so an
/// attacker cannot grow this by sending more requests.
#[derive(Default)]
struct SecurityCounters {
    auth_rejected: AtomicU64,
    forbidden: AtomicU64,
    rate_limited: AtomicU64,
    wrong_public_host: AtomicU64,
    honeypot: AtomicU64,
    unmatched_path: AtomicU64,
    /// Bucket evictions forced by a full rate-limiter table. A sustained rate
    /// means enforcement is being diluted and the bound needs review.
    rate_limiter_pressure: AtomicU64,
}

static SECURITY_COUNTERS: LazyLock<SecurityCounters> = LazyLock::new(SecurityCounters::default);

/// Classifies a finished request as a named security event, if it is one.
/// Returns the event label and its running total.
fn security_event(status: StatusCode, path: &str) -> Option<(&'static str, u64)> {
    let counters = &*SECURITY_COUNTERS;
    let (label, counter) = if status == StatusCode::MISDIRECTED_REQUEST {
        // Preserve the transport-boundary signal even when the requested path
        // also happens to be a lure.
        ("wrong_public_host", &counters.wrong_public_host)
    } else if is_honeypot_path(path) {
        ("honeypot", &counters.honeypot)
    } else {
        match status {
            StatusCode::UNAUTHORIZED => ("auth_rejected", &counters.auth_rejected),
            StatusCode::FORBIDDEN => ("forbidden", &counters.forbidden),
            StatusCode::TOO_MANY_REQUESTS => ("rate_limited", &counters.rate_limited),
            StatusCode::NOT_FOUND if path.ends_with("{unmatched}") => {
                ("unmatched_path", &counters.unmatched_path)
            }
            _ => return None,
        }
    };
    Some((label, counter.fetch_add(1, Ordering::Relaxed) + 1))
}

/// One structured line per request: method, redacted route, status. 5xx are
/// logged at error, security-relevant outcomes at warn, everything else at
/// info. No request/response bodies, no headers — nothing secret is ever
/// recorded, and the path is already redacted of user data.
/// Hard deadline for one request, handler and body reads included. Without
/// it, a client can open a request and trickle body bytes indefinitely — each
/// stalled request pins a hyper task and its buffers. The TLS ingress is
/// trusted for transport, not for slow-body policing. Thirty seconds covers
/// the slowest legitimate work (a full vault transaction on slow storage)
/// with an order of magnitude to spare.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

async fn request_deadline(request: Request, next: Next) -> Response {
    deadline(REQUEST_DEADLINE, request, next).await
}

async fn deadline(limit: Duration, request: Request, next: Next) -> Response {
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError(StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
    }
}

async fn request_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = redacted_path(request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if response.status().is_server_error() {
        tracing::error!(%method, path, status, latency_ms, "request");
    } else if let Some((event, total)) = security_event(response.status(), &path) {
        tracing::warn!(%method, path, status, latency_ms, event, total, "security");
    } else {
        tracing::info!(%method, path, status, latency_ms, "request");
    }
    response
}

// ─── Decoy routes ───
//
// Everything below is decoration on top of the real controls, never a
// substitute for one. It changes no authentication, authorization, quota or
// rate-limit decision; it reflects no request data; it keeps no request-scoped
// state; and it never fires on a genuine probe of a real endpoint — telling an
// attacker which of their payloads was detected just teaches them what to
// avoid. It exists so an unambiguous scanner hit is visible in the logs, and so
// whoever goes looking gets a wink instead of silence.

/// Paths no Bastion client ever requests: commodity config-leak, admin-panel,
/// backup-file and framework-introspection probes. A hit is therefore a certain
/// scanner rather than a mistyped URL, which is what makes it worth alerting on.
const HONEYPOT_PATHS: [&str; 14] = [
    "/.env",
    "/.git/config",
    "/.aws/credentials",
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/phpmyadmin",
    "/actuator/health",
    "/debug/pprof",
    "/api/v1/users",
    "/backup.sql",
    "/dump.sql",
    "/config.json",
    "/server-status",
];

/// Constant body. No request data is interpolated, so this cannot become a
/// reflection primitive, and every caller sees byte-identical bytes.
const HONEYPOT_BODY: &str = concat!(
    "{\"error\":\"not_found\",",
    "\"note\":\"good try — but not this time\",",
    "\"report\":\"Found something real? See /.well-known/security.txt for responsible disclosure.\"}"
);

fn is_honeypot_path(path: &str) -> bool {
    let path = path.strip_prefix("/v1").unwrap_or(path);
    HONEYPOT_PATHS.contains(&path)
}

/// Answers a scanner probe with a constant 404. The status, headers and body
/// are indistinguishable in kind from any other miss — the only difference is
/// the wink, and the warn-level `honeypot` event this route's path produces in
/// the request log.
async fn honeypot() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        HONEYPOT_BODY,
    )
        .into_response()
}

/// RFC 9116 disclosure policy. Points at the real reporting channel from
/// SECURITY.md so a researcher who pokes at the API finds the front door.
async fn security_txt() -> Response {
    let body = format!(
        "# Bastion — zero-knowledge password manager.\n\
         # The server holds only opaque ciphertext; the vault is sealed client-side.\n\
         # Reports about that boundary are the ones we care about most.\n\
         Contact: https://github.com/only4bandz/bastionvault/security/advisories/new\n\
         Policy: https://github.com/only4bandz/bastionvault/blob/main/SECURITY.md\n\
         Preferred-Languages: en, fr\n\
         Expires: {}\n\
         # Please do not degrade availability or touch data that is not yours.\n\
         # And if you got here from /.env: nice reflexes. Still nothing there.\n",
        // Keep the rolling horizon comfortably below RFC 9116's one-year
        // recommendation. The deployment acceptance probe verifies the public
        // well-known URI rather than an API-prefixed alias.
        rfc3339_utc(now_secs().saturating_add(180 * 24 * 60 * 60))
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Formats a Unix timestamp as an RFC 3339 UTC instant (`Expires` is mandatory
/// in a security.txt). Civil-from-days conversion, so no date dependency.
fn rfc3339_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days, shifted to a March-based year so leap
    // days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60
    )
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

fn canonical_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let address = single_header(headers, FORWARDED_FOR_HEADER)?
        .to_str()
        .ok()?
        .parse::<IpAddr>()
        .ok()?;
    Some(match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    })
}

/// Rate-limit key for a client address.
///
/// A single IPv6 address is not a meaningful unit of accountability: the
/// smallest routine end-site allocation is a /64, so keying on the full address
/// let one ordinary VPS present 2^64 distinct keys and walk through every
/// per-source limit at no cost. Aggregating to the /64 makes a source bucket
/// cost what it is supposed to cost.
///
/// IPv4 keeps full-address granularity — /32 is already the end-site unit, and
/// aggregating further would punish shared NATs.
fn source_bucket_key(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let mut prefix = address.octets();
            prefix[8..].fill(0);
            format!("{}/64", Ipv6Addr::from(prefix))
        }
    }
}

async fn production_transport_boundary(
    State(st): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(policy) = &st.transport else {
        // Development binds to loopback by default and has no trusted ingress.
        // Treat all direct requests as one local source instead of trusting a
        // caller-supplied forwarding header.
        request
            .extensions_mut()
            .insert(ClientSource(IpAddr::V4(Ipv4Addr::LOCALHOST)));
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
    let client_ip = canonical_client_ip(request.headers()).ok_or(ApiError(
        StatusCode::BAD_REQUEST,
        "trusted ingress did not attest client address",
    ))?;
    request.extensions_mut().insert(ClientSource(client_ip));
    Ok(next.run(request).await)
}

async fn security_headers(State(st): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    // Retrying after one complete token-bucket refill window is always safe.
    // Advertise that conservative upper bound so well-behaved clients back off
    // instead of hammering, per RFC 9110 §10.2.3.
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let window = st.rate_window.max(st.auth_rate_limits.window);
        if let Ok(value) = HeaderValue::from_str(&window.as_secs().max(1).to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Every authenticated response is specific to its bearer, and vault reads
    // now carry an ETag validator. `no-store` should already keep these out of
    // any shared cache; `Vary` states the dependency outright so an
    // intermediary that mishandles the first directive cannot serve one
    // account's response to another.
    headers.insert(header::VARY, HeaderValue::from_static("authorization"));
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
    // The list is deliberately exhaustive rather than representative: the two
    // that matter most for a credential store are `clipboard-read` (a copied
    // password lives on the OS clipboard for up to 30s) and `display-capture`
    // (a screen share of a revealed secret), and neither was covered before.
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), bluetooth=(), camera=(), \
             clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), \
             fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), \
             local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), \
             picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), \
             serial=(), usb=(), web-share=(), xr-spatial-tracking=()",
        ),
    );
    // Isolate any such document from cross-origin windows and embedders.
    // COOP severs the opener relationship; COEP refuses to pull in any
    // cross-origin subresource that has not opted in, so the pair also
    // prevents the document from being placed in a cross-origin-isolated
    // agent cluster it never asked to join.
    headers.insert(
        "cross-origin-embedder-policy",
        HeaderValue::from_static("require-corp"),
    );
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
    // `includeSubDomains` closes the sibling-hostname hole: without it an
    // attacker who can answer for any `*.vault.example.com` name still gets one
    // plaintext round trip to plant a cookie or run a downgrade. `preload`
    // extends the same guarantee to a browser's very first contact, before any
    // HSTS header has ever been seen. Both are load-bearing for a credential
    // store, and the production edge contract already requires HTTPS-only
    // service of the whole public authority.
    if st.transport.is_some() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }
    response
}

// ─── Shared state ───

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<Inner>>,
    /// Rate counters have their own short, synchronous critical sections.
    /// They must never serialize unrelated cache reads or durable mutations.
    rate_limiters: Arc<RateLimiters>,
    db: Db,
    token_ttl: Duration,
    session_absolute_ttl: Duration,
    session_rotation_grace: Duration,
    auth_slots: Arc<Semaphore>,
    vault_transaction_slots: Arc<Semaphore>,
    waiting_vault_transactions: Arc<AtomicUsize>,
    max_rate_entries: usize,
    max_source_rate_entries: usize,
    rate_window: Duration,
    auth_rate_limits: AuthRateLimits,
    transport: Option<TransportPolicy>,
    verification_origin: Option<String>,
    /// Per-deployment secret keying deterministic prelogin decoys.
    prelogin_decoy_seed: [u8; 32],
    /// KDF parameters a decoy claims: this deployment's most common.
    prelogin_decoy_kdf: KdfParams,
}

struct Inner {
    accounts: HashMap<String, AccountRecord>, // email -> account
    // Domain-separated token hash -> session. Raw bearer tokens never persist
    // in server state after the login response is constructed.
    sessions: HashMap<[u8; 32], Session>,
    /// Immediate predecessors retained only for a short in-flight grace
    /// period. They point to the active successor by hash; no raw token is
    /// retained after a response.
    rotated_sessions: HashMap<[u8; 32], RotatedSession>,
    /// When the expired-session sweep last ran. Expiry itself is enforced per
    /// token on every authenticated request; this only amortizes reclamation.
    sessions_swept_at: Instant,
}

#[derive(Default)]
struct RateLimiters {
    authenticated: Mutex<HashMap<String, RateState>>,
    authentication: Mutex<HashMap<String, RateState>>,
    /// Source buckets live apart from account buckets. Their keys are chosen by
    /// the caller — an address, not an identifier the server issued — so they
    /// must never be able to crowd an account or token bucket out of a shared
    /// table.
    source: Mutex<HashMap<String, RateState>>,
    /// Long-window allowances. A table's reclamation sweep drops entries idle
    /// for longer than the window it is called with, so buckets measured in
    /// days cannot share a table with buckets measured in minutes: one sweep
    /// for a per-minute limit would silently refill every standing allowance.
    standing: Mutex<HashMap<String, RateState>>,
}

/// Deterministic integer token bucket. `refill_remainder` carries fractional
/// tokens without floating-point drift.
struct RateState {
    updated_at: Instant,
    tokens: u32,
    refill_remainder: u128,
}

/// Active session: the token's owner and its expiration instant.
struct Session {
    email: String,
    family_id: [u8; 16],
    created_at: Instant,
    expires_at: Instant,
    /// Set the first time this token authenticates a request. It distinguishes
    /// "the client never received this successor" from "the client is using
    /// it", which is what lets a rotation retry be answered safely without
    /// retaining any raw token. Interior mutability keeps the read-lock fast
    /// path in `require_auth` from needing the write lock.
    used: AtomicBool,
}

struct RotatedSession {
    email: String,
    family_id: [u8; 16],
    successor_hash: [u8; 32],
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
            max_source_rate_entries,
            rate_window,
            auth_rate_limits,
            transport,
            smtp,
            verification_origin,
            session_absolute_ttl,
            session_rotation_grace,
        } = options;
        let (db, accounts, prelogin_decoy_seed) = Db::open(db_path);
        let prelogin_decoy_kdf = modal_kdf(&accounts);
        let state = Self {
            inner: Arc::new(RwLock::new(Inner {
                accounts,
                sessions: HashMap::new(),
                rotated_sessions: HashMap::new(),
                sessions_swept_at: Instant::now(),
            })),
            rate_limiters: Arc::new(RateLimiters::default()),
            db,
            token_ttl,
            session_absolute_ttl,
            session_rotation_grace,
            auth_slots: Arc::new(Semaphore::new(auth_limit)),
            vault_transaction_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_VAULT_TRANSACTIONS)),
            waiting_vault_transactions: Arc::new(AtomicUsize::new(0)),
            max_rate_entries,
            max_source_rate_entries,
            rate_window,
            auth_rate_limits,
            transport,
            verification_origin,
            prelogin_decoy_seed,
            prelogin_decoy_kdf,
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
    /// Number of accepted mutations that exceeded their response deadline and
    /// are still running. While non-zero, new storage work fails fast instead
    /// of piling up behind the single SQLite owner.
    timed_out_mutations: Arc<AtomicUsize>,
    response_timeout: Duration,
    /// Instant of the last storage probe that answered healthy. Readiness is
    /// served from it for `READINESS_CACHE_TTL` so unauthenticated probes cost
    /// at most one storage command per window.
    readiness_checked_at: Arc<Mutex<Option<Instant>>>,
    /// Single-flight admission for the unauthenticated readiness probe.
    readiness_probe: Arc<Semaphore>,
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

#[derive(Clone, Copy, Debug)]
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
    let mut random = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(random.as_mut());
    let partial_name = format!(
        ".{}.partial-{}",
        destination_name.to_string_lossy(),
        data_encoding::HEXLOWER.encode(random.as_ref())
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

fn migrate_v4_to_v5(conn: &mut Connection) -> rusqlite::Result<()> {
    // Account identifiers become canonical lowercase ASCII in v5. Rebuild all
    // related tables so the invariant is enforced by SQLite as well as the API
    // boundary. Foreign-key enforcement must be disabled outside the
    // transaction while the referenced tables are replaced.
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let migration = (|| {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let account_collision: bool = tx.query_row(
            "SELECT EXISTS(
               SELECT lower(email) AS canonical
                 FROM accounts
                GROUP BY canonical
               HAVING COUNT(*)>1
             )",
            [],
            |row| row.get(0),
        )?;
        let challenge_collision: bool = tx.query_row(
            "SELECT EXISTS(
               SELECT lower(c.email) AS canonical
                 FROM registration_challenges c
                WHERE NOT EXISTS(
                  SELECT 1 FROM accounts a WHERE lower(a.email)=lower(c.email)
                )
                GROUP BY canonical
               HAVING COUNT(*)>1
             )",
            [],
            |row| row.get(0),
        )?;
        if account_collision || challenge_collision {
            // Two independent vaults or proofs must never be merged by an
            // automatic case fold. The transaction leaves schema v4 untouched
            // so an operator can resolve the private records explicitly.
            //
            // This aborts startup, so the message has to be actionable: an
            // operator meeting it is mid-upgrade with a server that will not
            // come back until they act. It names the counts and the remedy, and
            // still never names an account.
            let colliding_accounts: i64 = tx.query_row(
                "SELECT COUNT(*) FROM accounts
                  WHERE lower(email) IN (
                    SELECT lower(email) FROM accounts
                     GROUP BY lower(email) HAVING COUNT(*)>1)",
                [],
                |row| row.get(0),
            )?;
            let colliding_challenges: i64 = tx.query_row(
                "SELECT COUNT(*) FROM registration_challenges c
                  WHERE NOT EXISTS(
                        SELECT 1 FROM accounts a WHERE lower(a.email)=lower(c.email))
                    AND lower(c.email) IN (
                        SELECT lower(email) FROM registration_challenges
                         GROUP BY lower(email) HAVING COUNT(*)>1)",
                [],
                |row| row.get(0),
            )?;
            return Err(stored_data_error(
                0,
                rusqlite::types::Type::Text,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "schema v5 canonicalizes account identifiers to lowercase, and this                          database holds {colliding_accounts} account row(s) and                          {colliding_challenges} registration-challenge row(s) that differ only                          by letter case. Merging them automatically could hand one person                          another's vault, so the migration refused and left the database at                          schema v4 — this server has not modified it. Resolve the duplicates                          (keep one account per lowercase address, delete or re-issue the                          affected challenges), then start this version again. To list them:                          SELECT lower(email), COUNT(*) FROM accounts GROUP BY 1 HAVING COUNT(*)>1"
                    ),
                ),
            ));
        }

        tx.execute_batch(
            "CREATE TABLE accounts_v5(
               email TEXT PRIMARY KEY,
               salt TEXT NOT NULL,
               kdf TEXT NOT NULL,
               wrapped_vault_key TEXT NOT NULL,
               auth_hash TEXT NOT NULL,
               vault_revision INTEGER NOT NULL DEFAULT 0,
               email_verified_at INTEGER,
               CHECK(email=lower(email)));
             INSERT INTO accounts_v5
               SELECT lower(email),salt,kdf,wrapped_vault_key,auth_hash,
                      vault_revision,email_verified_at
                 FROM accounts;

             CREATE TABLE items_v5(
               email TEXT NOT NULL,
               id TEXT NOT NULL,
               blob TEXT NOT NULL,
               PRIMARY KEY(email,id),
               FOREIGN KEY(email) REFERENCES accounts_v5(email) ON DELETE CASCADE,
               CHECK(email=lower(email)));
             INSERT INTO items_v5
               SELECT lower(email),id,blob FROM items;

             CREATE TABLE manifests_v5(
               email TEXT PRIMARY KEY,
               blob TEXT NOT NULL,
               FOREIGN KEY(email) REFERENCES accounts_v5(email) ON DELETE CASCADE,
               CHECK(email=lower(email)));
             INSERT INTO manifests_v5
               SELECT lower(email),blob FROM manifests;

             CREATE TABLE send_directory_v5(
               email TEXT PRIMARY KEY,
               bastion_id TEXT UNIQUE NOT NULL,
               public TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               FOREIGN KEY(email) REFERENCES accounts_v5(email) ON DELETE CASCADE,
               CHECK(email=lower(email)));
             INSERT INTO send_directory_v5
               SELECT lower(email),bastion_id,public,created_at FROM send_directory;

             CREATE TABLE send_inbox_v5(
               recipient_id TEXT NOT NULL,
               message_id TEXT NOT NULL,
               blob TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               expires_at INTEGER,
               PRIMARY KEY(recipient_id,message_id),
               FOREIGN KEY(recipient_id) REFERENCES send_directory_v5(bastion_id)
                 ON DELETE CASCADE);
             INSERT INTO send_inbox_v5
               SELECT recipient_id,message_id,blob,created_at,expires_at FROM send_inbox;

             CREATE TABLE registration_challenges_v5(
               email TEXT PRIMARY KEY,
               token_hash BLOB UNIQUE NOT NULL,
               expires_at INTEGER NOT NULL,
               resend_after INTEGER NOT NULL,
               verified_at INTEGER,
               created_at INTEGER NOT NULL,
               CHECK(email=lower(email)),
               CHECK(length(token_hash)=32),
               CHECK(expires_at>=created_at),
               CHECK(resend_after>=created_at),
               CHECK(verified_at IS NULL OR verified_at>=created_at));
             INSERT INTO registration_challenges_v5
               SELECT lower(c.email),c.token_hash,c.expires_at,c.resend_after,
                      c.verified_at,c.created_at
                 FROM registration_challenges c
                WHERE NOT EXISTS(
                  SELECT 1 FROM accounts a WHERE lower(a.email)=lower(c.email)
                );

             CREATE TABLE mail_outbox_v5(
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
               FOREIGN KEY(account_email) REFERENCES accounts_v5(email) ON DELETE CASCADE,
               FOREIGN KEY(challenge_email) REFERENCES registration_challenges_v5(email)
                 ON DELETE CASCADE,
               CHECK((account_email IS NOT NULL)+(challenge_email IS NOT NULL)=1),
               CHECK(account_email IS NULL OR account_email=lower(account_email)),
               CHECK(challenge_email IS NULL OR challenge_email=lower(challenge_email)),
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
             INSERT INTO mail_outbox_v5(
               id,account_email,challenge_email,recipient,subject,text_body,state,
               attempts,available_at,lease_until,created_at,delivered_at,last_error_code
             ) SELECT
               o.id,
               CASE WHEN o.account_email IS NULL THEN NULL ELSE lower(o.account_email) END,
               CASE WHEN o.challenge_email IS NULL THEN NULL ELSE lower(o.challenge_email) END,
               CASE WHEN o.recipient='' THEN '' ELSE lower(o.recipient) END,
               o.subject,o.text_body,o.state,o.attempts,o.available_at,o.lease_until,
               o.created_at,o.delivered_at,o.last_error_code
             FROM mail_outbox o
             WHERE o.account_email IS NOT NULL
                OR EXISTS(
                  SELECT 1 FROM registration_challenges_v5 c
                   WHERE c.email=lower(o.challenge_email)
                );

             DROP TABLE mail_outbox;
             DROP TABLE registration_challenges;
             DROP TABLE send_inbox;
             DROP TABLE send_directory;
             DROP TABLE items;
             DROP TABLE manifests;
             DROP TABLE accounts;

             ALTER TABLE accounts_v5 RENAME TO accounts;
             ALTER TABLE items_v5 RENAME TO items;
             ALTER TABLE manifests_v5 RENAME TO manifests;
             ALTER TABLE send_directory_v5 RENAME TO send_directory;
             ALTER TABLE send_inbox_v5 RENAME TO send_inbox;
             ALTER TABLE registration_challenges_v5 RENAME TO registration_challenges;
             ALTER TABLE mail_outbox_v5 RENAME TO mail_outbox;
             CREATE INDEX idx_inbox_recipient ON send_inbox(recipient_id);
             CREATE INDEX idx_mail_outbox_due
               ON mail_outbox(state,available_at,lease_until,created_at);
             PRAGMA user_version=5;",
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
            4 => migrate_v4_to_v5(conn)?,
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
                timed_out_mutations: Arc::new(AtomicUsize::new(0)),
                response_timeout,
                readiness_checked_at: Arc::new(Mutex::new(None)),
                readiness_probe: Arc::new(Semaphore::new(1)),
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
        let mut fresh = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(fresh.as_mut());
        conn.execute(
            "INSERT OR IGNORE INTO server_meta(key,value) VALUES('prelogin_decoy_seed',?1)",
            [fresh.as_slice()],
        )?;
        let stored: Vec<u8> = conn.query_row(
            "SELECT value FROM server_meta WHERE key='prelogin_decoy_seed'",
            [],
            |row| row.get(0),
        )?;
        stored.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
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
        if self.timed_out_mutations.load(Ordering::Acquire) != 0 {
            return Err(DbError::ResponseTimeout);
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
                // queue safely.
                //
                // A durable mutation must still finish while its logical cache
                // lock is held — that await, not the quarantine, is what keeps
                // a late commit from diverging the cache. So a slow mutation
                // that ultimately succeeds leaves storage perfectly consistent
                // and the instance stays in service. A completed SQLite error
                // is also unambiguous: its transaction did not commit and the
                // cache has not advanced. Only losing the worker makes the
                // durable outcome unknowable and quarantines the process.
                // Quarantining on slowness alone handed any client that could
                // make one command exceed the timeout a permanent,
                // restart-only outage for every account on the instance.
                //
                // Reads mutate nothing: a timed-out read is a load signal, and
                // the abandoned job is harmless when it eventually runs.
                if finish_after_timeout {
                    tracing::warn!(
                        timeout_ms = self.response_timeout.as_millis() as u64,
                        "storage mutation exceeded its response deadline; awaiting completion"
                    );
                    self.timed_out_mutations.fetch_add(1, Ordering::AcqRel);
                    let timed_out_mutations = self.timed_out_mutations.clone();
                    let available = self.available.clone();
                    // The detached monitor is deliberate: if the HTTP request
                    // is cancelled after the deadline, it still observes the
                    // accepted command to completion and re-opens admission.
                    // Dropping the caller must never leave the process stuck in
                    // a synthetic overload state or accept work while the
                    // abandoned mutation is still running.
                    tokio::spawn(async move {
                        let result = result_receiver.await.map_err(|_| {
                            available.store(false, Ordering::Release);
                            DbError::WorkerClosed
                        });
                        timed_out_mutations.fetch_sub(1, Ordering::AcqRel);
                        result
                    })
                    .await
                    .map_err(|_| {
                        self.available.store(false, Ordering::Release);
                        DbError::WorkerClosed
                    })??
                } else {
                    Err(DbError::ResponseTimeout)
                }
            }
        }
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    fn is_accepting_work(&self) -> bool {
        self.is_available() && self.timed_out_mutations.load(Ordering::Acquire) == 0
    }

    async fn ready(&self) -> Result<(), DbError> {
        if !self.is_available() {
            return Err(DbError::Quarantined);
        }
        if !self.is_accepting_work() {
            return Err(DbError::ResponseTimeout);
        }
        // Serve a recent healthy answer without touching storage. Only success
        // is cached: a failure must be re-observed, and it quarantines anyway.
        {
            let checked_at = self
                .readiness_checked_at
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if checked_at.is_some_and(|at| at.elapsed() < READINESS_CACHE_TTL) {
                return Ok(());
            }
        }
        // Do not let a cache-expiry stampede enqueue one SQLite command per
        // unauthenticated probe. One caller refreshes; concurrent callers fail
        // fast and the ingress retries on its next normal probe interval.
        let _probe = self
            .readiness_probe
            .clone()
            .try_acquire_owned()
            .map_err(|_| DbError::QueueFull)?;
        // Another caller may have refreshed between the first cache check and
        // this permit acquisition.
        {
            let checked_at = self
                .readiness_checked_at
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if checked_at.is_some_and(|at| at.elapsed() < READINESS_CACHE_TTL) {
                return Ok(());
            }
        }
        // Reads one row rather than counting the table: still fails closed on a
        // dropped or unreadable schema, without an O(n) scan per probe.
        let result = self
            .call(|conn| {
                conn.query_row("SELECT 1 FROM accounts LIMIT 1", [], |_| Ok(()))
                    .or_else(|error| match error {
                        rusqlite::Error::QueryReturnedNoRows => Ok(()),
                        error => Err(error),
                    })
            })
            .await;
        if result.is_ok() {
            *self
                .readiness_checked_at
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(Instant::now());
        }
        // A readiness *fault* means operators can no longer trust this process
        // to serve its cache consistently with durable state; recovery is a
        // restart after the storage fault is fixed. Saturation and slowness are
        // not faults: they answer 503 and withdraw traffic, then recover on
        // their own. Quarantining on those let an outsider convert a burst of
        // unauthenticated probes into a permanent outage.
        if matches!(&result, Err(DbError::Sqlite) | Err(DbError::WorkerClosed)) {
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
    ///
    /// `Immediate` (like every other mutation here): a deferred transaction
    /// only takes the write lock at its first write, so under a concurrent
    /// read-only connection (backup / ops-status) the mid-transaction lock
    /// upgrade can fail with SQLITE_BUSY after statements already ran.
    /// Failing up-front honors `busy_timeout` and keeps deletion all-or-nothing.
    async fn delete_account(&self, email: &str) -> Result<bool, DbError> {
        let email = email.to_owned();
        self.call_mutation(move |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
                    io::Error::new(io::ErrorKind::InvalidData, "orphaned persisted vault item")
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
                        "persisted vault item violates storage limits",
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
                        "orphaned persisted vault manifest",
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
                        "persisted vault manifest violates storage limits",
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
struct LoginResponse<'a> {
    token: &'a str,
}

/// Rotation carries no request fields: the replacement token is minted by the
/// server and returned in the response.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateSessionRequest {}

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

/// Canonical client address asserted by the same-host trusted ingress.
#[derive(Clone, Copy)]
struct ClientSource(IpAddr);

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
    let mut raw_token = Zeroizing::new([0u8; VERIFICATION_TOKEN_BYTES]);
    OsRng.fill_bytes(raw_token.as_mut());
    let token = URL_SAFE_NO_PAD.encode(raw_token.as_ref());
    let token_hash = Sha256::digest(raw_token.as_ref()).into();
    let mut raw_id = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(raw_id.as_mut());
    let outbox_id = data_encoding::HEXLOWER.encode(raw_id.as_ref());
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
    Extension(source): Extension<ClientSource>,
    Json(req): Json<RegistrationChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    let origin = st.verification_origin.as_deref().ok_or(ApiError(
        StatusCode::NOT_FOUND,
        "mailbox verification disabled",
    ))?;
    let email = canonical_account_id(&req.email)?;
    if !mail_outbox::valid_recipient(&email) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid mailbox"));
    }
    source_auth_rate_limit(
        &st,
        source,
        "challenge-source",
        MAX_CHALLENGES_PER_SOURCE_PER_MIN,
    )?;
    auth_rate_limit(
        &st,
        "global",
        "challenge-global",
        MAX_CHALLENGES_GLOBAL_PER_MIN,
    )?;
    auth_rate_limit(
        &st,
        &email,
        "challenge-email",
        MAX_CHALLENGES_PER_EMAIL_PER_MIN,
    )?;
    rate_limit_with_window(
        &st,
        &email,
        "challenge-email-day",
        MAX_CHALLENGES_PER_EMAIL_PER_DAY,
        CHALLENGE_EMAIL_DAY,
    )?;
    let mail = new_registration_mail(&email, origin, now_secs());
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
    Extension(source): Extension<ClientSource>,
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
    source_auth_rate_limit(
        &st,
        source,
        "verify-source",
        MAX_VERIFICATIONS_PER_SOURCE_PER_MIN,
    )?;
    auth_rate_limit(
        &st,
        "global",
        "verify-global",
        MAX_VERIFICATIONS_GLOBAL_PER_MIN,
    )?;
    let rate_key = data_encoding::HEXLOWER.encode(&token_hash[..8]);
    auth_rate_limit(
        &st,
        &rate_key,
        "verify-token",
        MAX_VERIFICATIONS_PER_TOKEN_PER_MIN,
    )?;
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
    Extension(source): Extension<ClientSource>,
    Json(mut req): Json<CreateAccount>,
) -> Result<StatusCode, ApiError> {
    req.email = canonical_account_id(&req.email)?;
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
    source_auth_rate_limit(
        &st,
        source,
        "account-create-source",
        MAX_ACCOUNT_CREATIONS_PER_SOURCE_PER_MIN,
    )?;
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
    // Mailbox proof is checked *before* anything that can reveal whether the
    // account exists. Answering 409 first turned registration into an
    // enumeration oracle that any caller could query with a well-formed but
    // bogus token — 409 for an existing mailbox, 403 for an unknown one —
    // which defeated the whole point of the prelogin decoy below.
    //
    // Behind a valid proof the disclosure is harmless: the caller has just
    // demonstrated control of that mailbox, so "an account exists here" is not
    // a secret being kept from them.
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
    // Reject a known duplicate before paying the Argon2 cost. The authoritative
    // collision check is repeated under the write lock after hashing.
    if st.read().await.accounts.contains_key(&req.email) {
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
    )?;
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
    inner
        .rotated_sessions
        .retain(|_, session| session.email != email);
    Ok(StatusCode::NO_CONTENT)
}

async fn prelogin(
    State(st): State<AppState>,
    Extension(source): Extension<ClientSource>,
    Path(email): Path<String>,
) -> Result<Json<Prelogin>, ApiError> {
    let email = canonical_account_id(&email)?;
    // Unauthenticated existence oracle: throttle before the account lookup so
    // bulk enumeration (and KDF-parameter harvesting) is rate-bound.
    source_auth_rate_limit(
        &st,
        source,
        "prelogin-source",
        MAX_PRELOGINS_PER_SOURCE_PER_MIN,
    )?;
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
        None => Ok(Json(prelogin_decoy(
            &st.prelogin_decoy_seed,
            st.prelogin_decoy_kdf,
            &email,
        ))),
    }
}

/// The KDF parameters a decoy should claim.
///
/// A decoy is only indistinguishable if it looks like the accounts that
/// actually exist here. Hardcoding `KdfParams::default()` was right for a
/// deployment whose accounts were all created by the shipped clients — they
/// always register with the defaults — and wrong for any deployment holding
/// accounts registered with other parameters, where every decoy announced
/// itself by not matching the local population.
///
/// The mode is used rather than a per-email sample: real parameters never
/// change for an existing account, so a decoy's must not drift either. The mode
/// only moves when the population itself does, and an empty deployment falls
/// back to the registration defaults.
fn modal_kdf(accounts: &HashMap<String, AccountRecord>) -> KdfParams {
    let mut tally: Vec<(KdfParams, usize)> = Vec::new();
    for account in accounts.values() {
        match tally.iter_mut().find(|(kdf, _)| *kdf == account.kdf) {
            Some((_, count)) => *count += 1,
            None => tally.push((account.kdf, 1)),
        }
    }
    tally
        .into_iter()
        // Ties resolve deterministically so restarts do not move the answer.
        .max_by_key(|(kdf, count)| (*count, kdf.mem_kib, kdf.iterations, kdf.parallelism))
        .map(|(kdf, _)| kdf)
        .unwrap_or_default()
}

/// Deterministic, secret-keyed decoy prelogin response for unknown accounts.
fn prelogin_decoy(seed: &[u8; 32], decoy_kdf: KdfParams, email: &str) -> Prelogin {
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
        // Same shape as a real registration, spelled with the same constants
        // real records are validated against: if the format version or any
        // envelope size ever moves, decoys move with it instead of announcing
        // themselves by shape.
        salt: B64_STD.encode(prf("prelogin-decoy:salt", REGISTRATION_SALT_BYTES)),
        kdf: decoy_kdf,
        wrapped_vault_key: EncryptedBlob {
            v: crypto_core::aead::FORMAT_VERSION,
            nonce: B64_STD.encode(prf("prelogin-decoy:nonce", WRAPPED_KEY_NONCE_BYTES)),
            ct: B64_STD.encode(prf("prelogin-decoy:ct", WRAPPED_KEY_CIPHERTEXT_BYTES)),
        },
    }
}

async fn create_session(
    State(st): State<AppState>,
    Extension(source): Extension<ClientSource>,
    Json(mut req): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    req.email = canonical_account_id(&req.email)?;
    if !is_exact_b64(req.auth_secret.expose_b64(), AUTH_SECRET_BYTES) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    source_auth_rate_limit(
        &st,
        source,
        "login-source",
        MAX_LOGIN_ATTEMPTS_PER_SOURCE_PER_MIN,
    )?;
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
    // One failure shape for every rejected login. A distinct 403 for "exists
    // but unverified" told an unauthenticated caller that the mailbox is
    // registered — the exact fact the identical 401 and the constant-cost dummy
    // verification above are there to hide. Production only ever creates
    // accounts whose mailbox is already proven, so this branch is reachable
    // only for legacy or development records.
    if !ok || !known || !mailbox_verified {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let now = Instant::now();
    let expires_at = now
        .checked_add(st.token_ttl.min(st.session_absolute_ttl))
        .ok_or(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session lifetime overflow",
        ))?;
    let mut inner = st.write().await;
    retain_live_sessions(&mut inner, now);
    // One liveness-aware pass for both the account's session count and its
    // oldest family. This ran as three separate full scans of a map holding up
    // to MAX_ACTIVE_SESSIONS entries, under the global write lock. The sweep
    // above is amortized, so expired entries may still be present and must be
    // skipped here rather than counted toward the per-account cap.
    let mut account_sessions = 0usize;
    let mut oldest: Option<([u8; 32], Instant)> = None;
    for (token_hash, session) in inner.sessions.iter() {
        if session.email != req.email || now >= session.expires_at {
            continue;
        }
        account_sessions += 1;
        if oldest.is_none_or(|(_, created_at)| session.created_at < created_at) {
            oldest = Some((*token_hash, session.created_at));
        }
    }
    if account_sessions >= MAX_SESSIONS_PER_ACCOUNT {
        if let Some((token_hash, _)) = oldest {
            if let Some(oldest) = inner.sessions.get(&token_hash) {
                let family_id = oldest.family_id;
                revoke_session_family(&mut inner, family_id);
            }
        }
    }
    if inner.sessions.len() >= MAX_ACTIVE_SESSIONS {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "session capacity reached",
        ));
    }
    let mut token = new_token();
    let mut token_hash = session_token_hash(&token);
    while inner.sessions.contains_key(&token_hash) {
        token = new_token();
        token_hash = session_token_hash(&token);
    }
    inner.sessions.insert(
        token_hash,
        Session {
            email: req.email,
            family_id: new_session_family_id(),
            created_at: now,
            expires_at,
            used: AtomicBool::new(false),
        },
    );
    login_response(&token)
}

/// Authenticate before Axum extracts the larger transaction body. This keeps
/// the expanded route-specific limit unavailable to unauthenticated callers.
async fn authenticate_vault_transaction(
    State(st): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let email = require_auth(&st, request.headers()).await?;
    rate_limit(&st, &email, "vault-write", MAX_VAULT_MUTATIONS_PER_MIN)?;
    request.extensions_mut().insert(AuthenticatedAccount(email));
    Ok(next.run(request).await)
}

/// An opaque, deployment-stable weak validator for one account revision.
///
/// The account is part of the authenticated representation even though every
/// caller uses the same `/vault` URI. A plain revision tag could therefore
/// produce a false 304 when a client switches accounts at the same revision.
/// HMAC keeps the account identifier out of the header while the persisted
/// deployment seed keeps validators stable across process restarts. The tag is
/// weak because equivalent `HashMap` content may serialize in a different key
/// order after restart; it intentionally asserts semantic, not byte identity.
fn vault_etag(seed: &[u8; 32], email: &str, revision: u64) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(seed).expect("SHA-256 HMAC accepts every key length");
    mac.update(b"bastion:v1:vault-etag\0");
    mac.update(
        &u64::try_from(email.len())
            .expect("validated account identifiers fit in u64")
            .to_be_bytes(),
    );
    mac.update(email.as_bytes());
    mac.update(&revision.to_be_bytes());
    format!(
        "W/\"{}\"",
        data_encoding::HEXLOWER.encode(mac.finalize().into_bytes().as_ref())
    )
}

/// Parse `If-None-Match` strictly enough to avoid treating malformed input as
/// an unconditional request. GET uses weak comparison, so `W/"tag"` matches
/// the equivalent `"tag"` form. Multiple field lines and comma-separated lists
/// are accepted; the wildcard may not be mixed with entity tags.
fn if_none_match_matches(headers: &HeaderMap, current: &str) -> Result<bool, ApiError> {
    let invalid = || ApiError(StatusCode::BAD_REQUEST, "invalid If-None-Match");
    let current_entity_tag = current.strip_prefix("W/").unwrap_or(current);
    let mut matched = false;
    let mut wildcard = false;
    let mut tag_count = 0usize;

    for value in headers.get_all(header::IF_NONE_MATCH).iter() {
        let raw = value.to_str().map_err(|_| invalid())?;
        for part in raw.split(',') {
            let candidate = part.trim_matches(|character| character == ' ' || character == '\t');
            if candidate.is_empty() {
                return Err(invalid());
            }
            if candidate == "*" {
                wildcard = true;
                continue;
            }

            tag_count = tag_count.saturating_add(1);
            let entity_tag = candidate.strip_prefix("W/").unwrap_or(candidate);
            let bytes = entity_tag.as_bytes();
            if bytes.len() < 2
                || bytes.first() != Some(&b'"')
                || bytes.last() != Some(&b'"')
                || !bytes[1..bytes.len() - 1]
                    .iter()
                    .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte))
            {
                return Err(invalid());
            }
            matched |= entity_tag == current_entity_tag;
        }
    }

    if wildcard && tag_count != 0 {
        return Err(invalid());
    }
    Ok(wildcard || matched)
}

async fn get_vault(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "vault-read", MAX_VAULT_READS_PER_MIN)?;
    let inner = st.read().await;
    let acc = inner
        .accounts
        .get(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let etag = vault_etag(&st.prelogin_decoy_seed, &email, acc.vault_revision);
    let etag_header = HeaderValue::from_str(&etag)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "etag error"))?;
    if if_none_match_matches(&headers, &etag)? {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(header::ETAG, etag_header);
        return Ok(response);
    }

    let payload = VaultResponse {
        items: acc.items.clone(),
        manifest: acc.manifest.clone(),
        revision: acc.vault_revision,
    };
    drop(inner);
    let mut response = Json(payload).into_response();
    response.headers_mut().insert(header::ETAG, etag_header);
    Ok(response)
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
    )?;
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

    // Acquire after extraction and validation but before the global cache lock.
    // This prevents a slow uploader from reserving the slot and prevents valid
    // requests from accumulating behind a transaction whose SQLite commit is
    // slow. The client can safely retry a 503 with its expected revision.
    let _transaction_slot = acquire_vault_transaction_slot(&st).await?;

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
    // The atomic transaction path admits writers through this same bucket;
    // the compatibility routes must not offer an unmetered bypass to the
    // write lock and its durable commit.
    rate_limit(&st, &email, "vault-write", MAX_VAULT_MUTATIONS_PER_MIN)?;
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
    rate_limit(&st, &email, "vault-write", MAX_VAULT_MUTATIONS_PER_MIN)?;
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
    rate_limit(&st, &email, "vault-write", MAX_VAULT_MUTATIONS_PER_MIN)?;
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

/// Canonical account identity used by storage, authentication, rate limits,
/// ETags, mailbox proofs, sessions, and client rollback scopes. Account ids are
/// already restricted to ASCII, so this fold is deterministic across Rust,
/// SQLite, JavaScript, SMTP providers, and process restarts.
fn canonical_account_id(email: &str) -> Result<String, ApiError> {
    validate_account_id(email)?;
    Ok(email.to_ascii_lowercase())
}

/// Admits one vault transaction into the global commit slot.
///
/// The slot is process-wide, not per account: while one transaction is
/// committing — a durable fsync under `synchronous=FULL` — nobody else may
/// hold it. Failing fast there meant an ordinary pair of concurrent writers
/// rejected each other, and gave one account issuing maximum-size
/// transactions at its full mutation allowance a cheap way to make every
/// other account's writes fail. A short bounded wait turns that contention
/// back into queueing, while the waiter ceiling keeps the queue itself from
/// becoming the resource under attack.
async fn acquire_vault_transaction_slot(st: &AppState) -> Result<OwnedSemaphorePermit, ApiError> {
    let waiting = st.waiting_vault_transactions.fetch_add(1, Ordering::AcqRel);
    let _waiter = WaitingTransaction(st.waiting_vault_transactions.clone());
    if waiting >= MAX_WAITING_VAULT_TRANSACTIONS {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "storage busy"));
    }
    match tokio::time::timeout(
        VAULT_TRANSACTION_ADMISSION_WAIT,
        st.vault_transaction_slots.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) | Err(_) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "storage busy")),
    }
}

/// Decrements the waiter count on every exit path, including cancellation.
struct WaitingTransaction(Arc<AtomicUsize>);

impl Drop for WaitingTransaction {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
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
    let valid = canonical_account_id(email).is_ok_and(|canonical| canonical == email)
        && is_exact_b64(salt, REGISTRATION_SALT_BYTES)
        && kdf_is_valid
        && wrapped.v == crypto_core::aead::FORMAT_VERSION
        && is_exact_b64(&wrapped.nonce, WRAPPED_KEY_NONCE_BYTES)
        && is_exact_b64(&wrapped.ct, WRAPPED_KEY_CIPHERTEXT_BYTES)
        && parse_valid_auth_hash(auth_hash).is_some();
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid persisted account credentials",
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

/// Rotates one session family to a client-generated replacement token.
///
/// The predecessor remains usable for a short grace period so requests that
/// were already dispatched do not fail underneath the client. Repeating the
/// exact request through that predecessor is idempotent; a different proposed
/// successor is rejected. The access deadline may slide, but `created_at`
/// survives every rotation and enforces the absolute session ceiling.
async fn rotate_session(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(_): Json<RotateSessionRequest>,
) -> Result<Response, ApiError> {
    let predecessor_hash = session_token_hash(bearer_token(&headers)?);
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "session-control", 30)?;

    let now = Instant::now();
    let mut inner = st.write().await;
    retain_live_sessions(&mut inner, now);

    // Lost-response retry.
    //
    // The client cannot name the successor — it never chose it and, if the
    // response was lost, never saw it. What separates a retry from an attempt
    // to mint a second live token off one predecessor is whether the successor
    // has ever authenticated a request:
    //
    //   never used   → the client did not receive it. Revoke that token and
    //                  answer with a fresh one.
    //   already used → the legitimate client holds it, so this predecessor is
    //                  being replayed. That is the classic reuse signal, and
    //                  the whole family is revoked rather than extended.
    //
    // Either way the absolute ceiling is carried over from the family, so a
    // retry cannot be used to restart a session's lifetime.
    if let Some(rotated) = live_predecessor(&inner, &predecessor_hash, now) {
        let successor_hash = rotated.successor_hash;
        let family_id = rotated.family_id;
        let undelivered = live_session(&inner, &successor_hash, now).and_then(|successor| {
            (successor.family_id == family_id && !successor.used.load(Ordering::Acquire))
                .then_some(successor.created_at)
        });
        let Some(created_at) = undelivered else {
            revoke_session_family(&mut inner, family_id);
            tracing::warn!(event = "session_reuse_detected", "security");
            return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token"));
        };
        inner.sessions.remove(&successor_hash);
        inner.rotated_sessions.remove(&predecessor_hash);
        return install_rotated_session(
            &st,
            &mut inner,
            predecessor_hash,
            SessionFamily {
                email,
                family_id,
                created_at,
            },
            now,
        );
    }

    // Removing without checking would let an expired-but-unreclaimed token be
    // rotated into a fresh access window.
    if live_session(&inner, &predecessor_hash, now).is_none() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    let session = inner
        .sessions
        .remove(&predecessor_hash)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let family = SessionFamily {
        email: session.email,
        family_id: session.family_id,
        created_at: session.created_at,
    };
    install_rotated_session(&st, &mut inner, predecessor_hash, family, now)
}

/// The identity and lifetime a rotation carries forward. `created_at` survives
/// every rotation, so the absolute session ceiling holds however often a client
/// rotates — including across a retry.
struct SessionFamily {
    email: String,
    family_id: [u8; 16],
    created_at: Instant,
}

/// Mints the replacement token for `predecessor_hash` and installs it, keeping
/// the predecessor usable for the bounded in-flight grace period.
fn install_rotated_session(
    st: &AppState,
    inner: &mut Inner,
    predecessor_hash: [u8; 32],
    family: SessionFamily,
    now: Instant,
) -> Result<Response, ApiError> {
    let overflow = || {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session lifetime overflow",
        )
    };
    let absolute_expires_at = family
        .created_at
        .checked_add(st.session_absolute_ttl)
        .ok_or_else(overflow)?;
    if now >= absolute_expires_at {
        revoke_session_family(inner, family.family_id);
        return Err(ApiError(StatusCode::UNAUTHORIZED, "session expired"));
    }
    let access_expires_at = now
        .checked_add(st.token_ttl)
        .map(|candidate| candidate.min(absolute_expires_at))
        .ok_or_else(overflow)?;
    let grace_expires_at = now
        .checked_add(st.session_rotation_grace)
        .map(|candidate| candidate.min(absolute_expires_at))
        .ok_or_else(overflow)?;

    // Server-minted, exactly like the token issued at login. The replacement
    // used to be supplied by the client, which delegated the entropy of the
    // server's own bearer credential to whatever generator the caller happened
    // to use: the server could check its shape but never its randomness.
    let mut token = new_token();
    let mut successor_hash = session_token_hash(&token);
    while inner.sessions.contains_key(&successor_hash)
        || inner.rotated_sessions.contains_key(&successor_hash)
    {
        token = new_token();
        successor_hash = session_token_hash(&token);
    }

    // Keep at most one predecessor for each active family. This bounds grace
    // state to the active-session cap even if a client rotates repeatedly.
    inner
        .rotated_sessions
        .retain(|_, rotated| rotated.family_id != family.family_id);
    inner.sessions.insert(
        successor_hash,
        Session {
            email: family.email.clone(),
            family_id: family.family_id,
            created_at: family.created_at,
            expires_at: access_expires_at,
            used: AtomicBool::new(false),
        },
    );
    inner.rotated_sessions.insert(
        predecessor_hash,
        RotatedSession {
            email: family.email,
            family_id: family.family_id,
            successor_hash,
            expires_at: grace_expires_at,
        },
    );
    login_response(&token)
}

/// Revokes the current session family (logout), including a live successor if
/// the caller is using the short-lived predecessor after rotation.
async fn delete_session(
    State(st): State<AppState>,
    Extension(source): Extension<ClientSource>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let token_hash = session_token_hash(bearer_token(&headers)?);
    source_auth_rate_limit(&st, source, "logout-source", MAX_LOGOUTS_PER_SOURCE_PER_MIN)?;
    // Deliberately not filtered through the liveness accessors. Revocation is
    // the one direction where honouring a stale token is the safer default: a
    // client logging out with a predecessor whose grace has lapsed should still
    // be able to kill the family's live successor. Nothing is granted here.
    //
    // Probe under the SHARED lock first: any shape-valid token reaches this
    // handler, so an anonymous caller spraying random tokens must not
    // serialize logins, rotations, and vault writes behind exclusive
    // write-lock acquisitions. Only a hit pays for the write lock.
    let probed = {
        let inner = st.read().await;
        session_family(&inner, &token_hash)
    };
    if probed.is_some() {
        let mut inner = st.write().await;
        // Re-resolve under the write lock: the family may have rotated or
        // been revoked between the probe and the upgrade.
        if let Some(family_id) = session_family(&inner, &token_hash) {
            revoke_session_family(&mut inner, family_id);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Family lookup by token hash across live and grace-period sessions.
fn session_family(inner: &Inner, token_hash: &[u8; 32]) -> Option<[u8; 16]> {
    inner
        .sessions
        .get(token_hash)
        .map(|session| session.family_id)
        .or_else(|| {
            inner
                .rotated_sessions
                .get(token_hash)
                .map(|session| session.family_id)
        })
}

/// Revokes every active session for the authenticated account, including the
/// caller. This is intentionally process-local: sessions are never persisted,
/// and a process restart already invalidates every bearer token.
async fn delete_all_sessions(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "session-control", 30)?;
    let mut inner = st.write().await;
    inner.sessions.retain(|_, session| session.email != email);
    inner
        .rotated_sessions
        .retain(|_, session| session.email != email);
    tracing::warn!(event = "sessions_revoked_all", "security");
    Ok(StatusCode::NO_CONTENT)
}

/// Extracts the "Authorization: Bearer …" token.
fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    single_header(headers, header::AUTHORIZATION.as_str())
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|token| is_session_token(token))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))
}

fn is_session_token(token: &str) -> bool {
    token.len() == SESSION_TOKEN_HEX_CHARS
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validates the token (existence + non-expiration) and returns the email.
/// A predecessor remains valid only while its active successor exists and the
/// bounded rotation grace has not elapsed. Expired state is evicted along the
/// way.
async fn require_auth(st: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token_hash = session_token_hash(bearer_token(headers)?);
    let now = Instant::now();
    // Fast path: a valid, unexpired token needs only a READ lock, so concurrent
    // authenticated requests (every GET /vault, /send/inbox…) don't serialize on
    // the global write lock just to be validated.
    {
        let inner = st.read().await;
        if let Some(session) = live_session(&inner, &token_hash, now) {
            // Records that this token has served a request. A rotation retry
            // uses it to tell "the client never received this successor" from
            // "the client is using it".
            session.used.store(true, Ordering::Release);
            return Ok(session.email.clone());
        }
        if let Some(rotated) = live_predecessor(&inner, &token_hash, now) {
            return Ok(rotated.email.clone());
        }
    }
    // Slow path: take the write lock, reclaim expired state, and re-check in
    // case a concurrent rotation completed between locks. Liveness still comes
    // from the record's own deadline, never from reclamation having run.
    let mut inner = st.write().await;
    retain_live_sessions(&mut inner, now);
    if let Some(session) = live_session(&inner, &token_hash, now) {
        session.used.store(true, Ordering::Release);
        return Ok(session.email.clone());
    }
    if let Some(rotated) = live_predecessor(&inner, &token_hash, now) {
        return Ok(rotated.email.clone());
    }
    Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))
}

/// Reclaims memory held by expired sessions.
///
/// This sweep is not what makes an expired token unusable — every authorization
/// decision compares the record's own deadline through `live_session` /
/// `live_predecessor` — so it is pure housekeeping and does not have to run on
/// every request. It used to: a full scan of both maps, under the global write
/// lock, on every login and every rotation. That made the cost of those
/// requests O(active sessions) rather than O(1), and rotation is available 30
/// times a minute to every account, so the amplification grew with the number
/// of accounts an attacker controlled.
///
/// The capacity clause is load-bearing: the active-session ceiling is measured
/// against this map's length, so it must never be compared while the map is
/// padded with expired entries.
fn retain_live_sessions(inner: &mut Inner, now: Instant) {
    if now.saturating_duration_since(inner.sessions_swept_at) < SESSION_SWEEP_INTERVAL
        && inner.sessions.len() < MAX_ACTIVE_SESSIONS
    {
        return;
    }
    inner.sessions_swept_at = now;
    sweep_live_sessions(inner, now);
}

/// The unconditional sweep.
fn sweep_live_sessions(inner: &mut Inner, now: Instant) {
    inner.sessions.retain(|_, session| now < session.expires_at);
    let sessions = &inner.sessions;
    inner.rotated_sessions.retain(|_, rotated| {
        now < rotated.expires_at
            && sessions
                .get(&rotated.successor_hash)
                .is_some_and(|successor| successor.family_id == rotated.family_id)
    });
}

/// The session for `token_hash`, if it is live *right now*.
///
/// Liveness is a property of the record, never of whether reclamation happened
/// to run on this request. Reading the map directly and trusting the sweep is
/// what made an expired token briefly acceptable once already; every
/// authorization decision goes through here so that cannot be reintroduced by
/// changing when the sweep runs, or by calling a handler in a different order.
fn live_session<'a>(inner: &'a Inner, token_hash: &[u8; 32], now: Instant) -> Option<&'a Session> {
    inner
        .sessions
        .get(token_hash)
        .filter(|session| now < session.expires_at)
}

/// The rotation predecessor for `token_hash`, if it is still inside its grace
/// window *and* its successor is itself live and in the same family.
fn live_predecessor<'a>(
    inner: &'a Inner,
    token_hash: &[u8; 32],
    now: Instant,
) -> Option<&'a RotatedSession> {
    let rotated = inner.rotated_sessions.get(token_hash)?;
    if now >= rotated.expires_at {
        return None;
    }
    let successor = live_session(inner, &rotated.successor_hash, now)?;
    (successor.family_id == rotated.family_id).then_some(rotated)
}

fn revoke_session_family(inner: &mut Inner, family_id: [u8; 16]) {
    inner
        .sessions
        .retain(|_, session| session.family_id != family_id);
    inner
        .rotated_sessions
        .retain(|_, session| session.family_id != family_id);
}

/// Process-constant dummy PHC hash of a random secret nobody knows.
///
/// Logins for unknown accounts verify against this hash so they pay the same
/// Argon2id cost as a wrong password for a real account. Without it, response
/// time separated "no such account" (~µs) from "wrong secret" (~100 ms),
/// re-opening the account-enumeration oracle the identical 401 body closes.
static DUMMY_PHC: LazyLock<String> = LazyLock::new(|| {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    let encoded = Zeroizing::new(data_encoding::BASE64.encode(secret.as_ref()));
    hash_secret(encoded.as_str()).expect("hash dummy login secret")
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
/// The raw bearer credential is wiped when the caller is done with it —
/// including any collision-loop discard, which drops (and therefore
/// zeroizes) automatically on reassignment.
fn new_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; SESSION_TOKEN_BYTES]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(data_encoding::HEXLOWER.encode(bytes.as_ref()))
}

/// Serializes the login/rotation body inside the handler so the only copy of
/// the raw token that survives it is the response body itself (the bytes that
/// go on the wire). `Json(LoginResponse { token })` kept an extra unwiped
/// heap `String` alive past the handler.
fn login_response(token: &str) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(&LoginResponse { token })
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "serialize error"))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

fn new_session_family_id() -> [u8; 16] {
    let mut family_id = [0u8; 16];
    OsRng.fill_bytes(&mut family_id);
    family_id
}

fn session_token_hash(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bastion-session-token-v1\0");
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

// ════════════════════════════════════════════════════════════════════════════
//  Bastion Send — directory + inbox (server stores only opaque blobs + public
//  keys; see docs/bastion-send-design.md §4/§8). The server never sees plaintext
//  or any private key. recipient_id / message_id are routing metadata only.
// ════════════════════════════════════════════════════════════════════════════

/// New 128-bit opaque Bastion ID (base32, non-enumerable).
fn new_bastion_id() -> String {
    let mut bytes = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(bytes.as_mut());
    data_encoding::BASE32_NOPAD.encode(bytes.as_ref())
}

/// Per-key token bucket with an integer refill accumulator. New keys are
/// rejected when the strictly bounded state map is full and no idle bucket can
/// be reclaimed.
fn rate_limit_map(
    rate: &mut HashMap<String, RateState>,
    max_entries: usize,
    window: Duration,
    subject: &str,
    bucket: &str,
    max: u32,
) -> Result<(), ApiError> {
    rate_limit_map_at(
        rate,
        max_entries,
        window,
        subject,
        bucket,
        max,
        Instant::now(),
    )
}

fn rate_limit_map_at(
    rate: &mut HashMap<String, RateState>,
    max_entries: usize,
    window: Duration,
    subject: &str,
    bucket: &str,
    max: u32,
    now: Instant,
) -> Result<(), ApiError> {
    if max == 0 {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let key = format!("{bucket}\0{subject}");

    if let Some(entry) = rate.get_mut(&key) {
        if window.is_zero() {
            entry.updated_at = now;
            entry.tokens = max.saturating_sub(1);
            entry.refill_remainder = 0;
            return Ok(());
        }

        let generated = now
            .saturating_duration_since(entry.updated_at)
            .as_nanos()
            .saturating_mul(u128::from(max))
            .saturating_add(entry.refill_remainder);
        let window_nanos = window.as_nanos();
        let refilled = generated / window_nanos;
        let missing = u128::from(max.saturating_sub(entry.tokens));
        let (available, remainder) = if refilled >= missing {
            // A full bucket cannot bank additional idle time for a later burst.
            (max, 0)
        } else {
            (
                entry.tokens.saturating_add(refilled as u32),
                generated % window_nanos,
            )
        };
        if available == 0 {
            // Do not advance the accumulator on rejection. Repeated denied
            // requests therefore cannot pin the key or postpone its refill.
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
        }
        entry.updated_at = now;
        entry.tokens = available - 1;
        entry.refill_remainder = remainder;
        return Ok(());
    }

    if rate.len() >= max_entries {
        rate.retain(|_, entry| now.saturating_duration_since(entry.updated_at) < window);
    }

    // Every bucket refills completely after one window, so an entry that has
    // been idle that long carries no enforcement and was already dropped above.
    // If the table is still full, evict the least recently used entry instead of
    // refusing the newcomer: answering 503 here let anyone who could mint keys
    // faster than the table drains — a caller rotating source addresses, or a
    // flood of distinct account ids — deny service to every subject that did not
    // already hold an entry. Eviction degrades enforcement for the single
    // stalest key rather than availability for everyone.
    if rate.len() >= max_entries {
        let stalest = rate
            .iter()
            .min_by_key(|(_, entry)| entry.updated_at)
            .map(|(key, _)| key.clone());
        match stalest {
            Some(stalest) => {
                rate.remove(&stalest);
                SECURITY_COUNTERS
                    .rate_limiter_pressure
                    .fetch_add(1, Ordering::Relaxed);
            }
            // Unreachable while max_entries > 0; fail closed rather than grow.
            None => {
                return Err(ApiError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "rate limiter capacity reached",
                ))
            }
        }
    }

    rate.insert(
        key,
        RateState {
            updated_at: now,
            tokens: max - 1,
            refill_remainder: 0,
        },
    );
    Ok(())
}

/// Authenticated abuse limits are kept separate from unauthenticated auth
/// limits so an attacker cannot consume one subsystem's counter capacity
/// through the other. The standard mutex is intentional: this bounded map
/// operation cannot await and must not contend on the account/session lock.
fn rate_limit(st: &AppState, subject: &str, bucket: &str, max: u32) -> Result<(), ApiError> {
    let mut rate = st
        .rate_limiters
        .authenticated
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    rate_limit_map(
        &mut rate,
        st.max_rate_entries,
        st.rate_window,
        subject,
        bucket,
        max,
    )
}

/// Authenticated limit over an explicit window, for allowances whose point is
/// the standing total rather than the instantaneous rate.
fn rate_limit_with_window(
    st: &AppState,
    subject: &str,
    bucket: &str,
    max: u32,
    window: Duration,
) -> Result<(), ApiError> {
    let mut rate = st
        .rate_limiters
        .standing
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    rate_limit_map(&mut rate, st.max_rate_entries, window, subject, bucket, max)
}

fn auth_rate_limit(st: &AppState, subject: &str, bucket: &str, max: u32) -> Result<(), ApiError> {
    let mut rate = st
        .rate_limiters
        .authentication
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    rate_limit_map(
        &mut rate,
        st.auth_rate_limits.max_entries,
        st.auth_rate_limits.window,
        subject,
        bucket,
        max,
    )
}

/// Per-source admission. Keyed by the aggregated source bucket and held in a
/// table of its own, so caller-chosen keys can neither be minted for free nor
/// crowd out an account or token bucket.
fn source_auth_rate_limit(
    st: &AppState,
    source: ClientSource,
    bucket: &str,
    max: u32,
) -> Result<(), ApiError> {
    let mut rate = st
        .rate_limiters
        .source
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    rate_limit_map(
        &mut rate,
        st.max_source_rate_entries,
        st.auth_rate_limits.window,
        &source_bucket_key(source.0),
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

    /// Physically removes messages whose TTL has elapsed.
    async fn purge_expired(&self, recipient_id: &str, now: i64) -> Result<(), DbError> {
        let recipient_id = recipient_id.to_owned();
        self.call_mutation(move |conn| purge_expired_rows(conn, &recipient_id, now))
            .await
    }

    /// Purges the recipient's expired messages and returns the live page in a
    /// single storage command.
    ///
    /// These were two round trips through the single SQLite owner on every
    /// inbox read. They belong together: the TTL is a deletion promise rather
    /// than a display rule, so the purge must stay on the read path, and a
    /// purge that cannot run must fail the read instead of silently serving a
    /// listing whose expired rows were never removed.
    async fn purge_and_list_inbox(
        &self,
        recipient_id: &str,
        now: i64,
    ) -> Result<Vec<InboxItem>, DbError> {
        let recipient_id = recipient_id.to_owned();
        self.call_mutation(move |conn| {
            purge_expired_rows(conn, &recipient_id, now)?;
            list_inbox_rows(conn, &recipient_id, now)
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

/// Deletes every message of `recipient_id` whose deadline has passed, refusing
/// to act on rows whose stored timestamps are not self-consistent.
fn purge_expired_rows(conn: &mut Connection, recipient_id: &str, now: i64) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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

/// Returns one bounded page of the recipient's live messages, validating every
/// stored field rather than trusting persistence.
fn list_inbox_rows(
    conn: &Connection,
    recipient_id: &str,
    now: i64,
) -> rusqlite::Result<Vec<InboxItem>> {
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
            expires_at <= created_at || expires_at > created_at.saturating_add(MAX_SEND_TTL_SECS)
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
    rate_limit(
        &st,
        &email,
        "identity-publish",
        MAX_IDENTITY_PUBLICATIONS_PER_MIN,
    )?;
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
    rate_limit(&st, &email, "whoami", MAX_WHOAMI_READS_PER_MIN)?;
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
    rate_limit(&st, &email, "lookup", MAX_LOOKUPS_PER_MIN)?;
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
    // A single sender may consume only part of a recipient's aggregate budget.
    // Check this first: once that pair is blocked it cannot keep burning the
    // victim's shared inbound allowance.
    let sender_recipient = format!("{email}\0{}", body.recipient_id);
    rate_limit(
        &st,
        &sender_recipient,
        "inbound-pair",
        MAX_INBOUND_PER_SENDER_RECIPIENT_PER_MIN,
    )?;
    // The per-minute limit slows a flood; this one bounds how much of the
    // recipient's finite inbox a single sender can occupy, so filling it and
    // denying delivery to everyone else is no longer a twenty-minute job for
    // one account.
    rate_limit_with_window(
        &st,
        &sender_recipient,
        "inbound-pair-day",
        MAX_INBOUND_PER_SENDER_RECIPIENT_PER_DAY,
        INBOUND_PAIR_DAY,
    )?;
    // Aggregate recipient throttle still caps coordinated/multi-account floods.
    rate_limit(&st, &body.recipient_id, "inbound", MAX_INBOUND_PER_MIN)?;
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
    rate_limit(&st, &email, "inbox-read", MAX_INBOX_READS_PER_MIN)?;
    let mine = st
        .db
        .bastion_id_for(&email)
        .await
        .map_err(db_api_error)?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no identity published"))?;
    let now = now_secs();
    // Purge and list in one storage command. The TTL is a deletion promise, not
    // a display rule, so the purge stays on the read path — but it used to cost
    // a second round trip through the single SQLite owner on every one of the
    // 60 reads a minute each account is allowed. Failure still propagates: a
    // purge that cannot run fails the read rather than silently serving a
    // listing whose expired rows were never removed.
    let items = st
        .db
        .purge_and_list_inbox(&mine, now)
        .await
        .map_err(db_api_error)?;
    Ok(Json(items))
}

/// Delete a message from the caller's inbox (read-once / after processing).
async fn send_inbox_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers).await?;
    rate_limit(&st, &email, "inbox-delete", MAX_INBOX_DELETES_PER_MIN)?;
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

    #[tokio::test]
    async fn requests_past_the_deadline_return_408_and_fast_ones_pass() {
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    "late"
                }),
            )
            .route("/fast", get(|| async { "ok" }))
            .layer(middleware::from_fn(|request, next| {
                deadline(Duration::from_millis(20), request, next)
            }));

        let slow = Request::builder().uri("/slow").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(slow).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

        let fast = Request::builder().uri("/fast").body(Body::empty()).unwrap();
        let response = app.oneshot(fast).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn decoy_prelogin_passes_the_same_structural_checks_as_real_credentials() {
        // A decoy that fails the validator real records are held to would be
        // distinguishable by shape the moment the envelope format moves.
        let decoy = prelogin_decoy(&[7u8; 32], KdfParams::default(), "ghost@example.com");
        assert!(is_exact_b64(&decoy.salt, REGISTRATION_SALT_BYTES));
        assert_eq!(decoy.wrapped_vault_key.v, crypto_core::aead::FORMAT_VERSION);
        assert!(is_exact_b64(
            &decoy.wrapped_vault_key.nonce,
            WRAPPED_KEY_NONCE_BYTES
        ));
        assert!(is_exact_b64(
            &decoy.wrapped_vault_key.ct,
            WRAPPED_KEY_CIPHERTEXT_BYTES
        ));
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

    #[tokio::test]
    async fn rate_counters_do_not_contend_on_the_account_cache_lock() {
        let st = AppState::new(
            DEFAULT_TOKEN_TTL,
            ":memory:",
            MAX_CONCURRENT_AUTH,
            RuntimeOptions::default(),
        );
        let _account_cache = st.write().await;

        // These calls are synchronous and complete while the account cache
        // write lock is held. Regressing either limiter into `Inner` would
        // deadlock this test at the call site.
        assert!(rate_limit(&st, "account@example.com", "vault-read", 1).is_ok());
        assert!(auth_rate_limit(&st, "account@example.com", "login-account", 1).is_ok());
    }

    #[test]
    fn token_bucket_refills_gradually_without_a_window_boundary_burst() {
        let mut rate = HashMap::new();
        let start = Instant::now();
        let window = Duration::from_secs(60);

        assert!(rate_limit_map_at(&mut rate, 1, window, "source", "login", 2, start).is_ok());
        assert!(rate_limit_map_at(&mut rate, 1, window, "source", "login", 2, start).is_ok());
        assert!(rate_limit_map_at(&mut rate, 1, window, "source", "login", 2, start).is_err());
        assert!(rate_limit_map_at(
            &mut rate,
            1,
            window,
            "source",
            "login",
            2,
            start + Duration::from_secs(29),
        )
        .is_err());
        assert!(rate_limit_map_at(
            &mut rate,
            1,
            window,
            "source",
            "login",
            2,
            start + Duration::from_secs(30),
        )
        .is_ok());
        assert!(rate_limit_map_at(
            &mut rate,
            1,
            window,
            "source",
            "login",
            2,
            start + Duration::from_secs(30),
        )
        .is_err());
        assert!(rate_limit_map_at(
            &mut rate,
            1,
            window,
            "source",
            "login",
            2,
            start + Duration::from_secs(60),
        )
        .is_ok());
    }

    #[tokio::test]
    async fn concurrent_vault_transactions_queue_instead_of_rejecting_each_other() {
        let state = AppState::new(
            DEFAULT_TOKEN_TTL,
            ":memory:",
            MAX_CONCURRENT_AUTH,
            RuntimeOptions::default(),
        );
        // The commit slot is global, so a second writer used to be rejected
        // outright while the first was committing. It must now wait.
        let held = acquire_vault_transaction_slot(&state)
            .await
            .ok()
            .expect("first writer holds the slot");
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move { acquire_vault_transaction_slot(&state).await.is_ok() })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "second writer was not made to wait");
        drop(held);
        assert!(waiter.await.unwrap(), "second writer never got the slot");
    }

    #[tokio::test]
    async fn vault_transaction_waiting_is_itself_bounded() {
        let state = AppState::new(
            DEFAULT_TOKEN_TTL,
            ":memory:",
            MAX_CONCURRENT_AUTH,
            RuntimeOptions::default(),
        );
        let _held = acquire_vault_transaction_slot(&state)
            .await
            .ok()
            .expect("first writer holds the slot");
        // Waiting must not become an unbounded queue of its own.
        state
            .waiting_vault_transactions
            .store(MAX_WAITING_VAULT_TRANSACTIONS, Ordering::Release);
        assert!(acquire_vault_transaction_slot(&state).await.is_err());
        // The ceiling is released again on every exit path.
        assert_eq!(
            state.waiting_vault_transactions.load(Ordering::Acquire),
            MAX_WAITING_VAULT_TRANSACTIONS
        );
    }

    #[test]
    fn source_buckets_aggregate_ipv6_to_the_end_site_prefix() {
        // A /64 is the smallest routine end-site allocation, so every address
        // inside one must share a bucket. Keying on the full address let one
        // ordinary VPS present 2^64 distinct keys and walk through every
        // per-source limit at no cost.
        let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let second: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let neighbour: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_bucket_key(first), source_bucket_key(second));
        assert_ne!(source_bucket_key(first), source_bucket_key(neighbour));
        assert_eq!(source_bucket_key(first), "2001:db8:1:2::/64");

        // IPv4 keeps full-address granularity: /32 is already the end-site
        // unit, and aggregating further would punish shared NATs.
        let v4: IpAddr = "192.0.2.44".parse().unwrap();
        let v4_neighbour: IpAddr = "192.0.2.45".parse().unwrap();
        assert_eq!(source_bucket_key(v4), "192.0.2.44");
        assert_ne!(source_bucket_key(v4), source_bucket_key(v4_neighbour));
    }

    fn expired_session(email: &str, now: Instant) -> Session {
        Session {
            email: email.to_string(),
            family_id: [0u8; 16],
            created_at: now,
            expires_at: now,
            used: AtomicBool::new(false),
        }
    }

    #[test]
    fn the_active_session_ceiling_is_never_measured_against_unreclaimed_state() {
        // Login compares sessions.len() with MAX_ACTIVE_SESSIONS. Reclamation
        // is amortized, so that comparison is only meaningful because the sweep
        // is forced once the map reaches the ceiling. Without that clause the
        // server would answer "session capacity reached" to legitimate logins
        // while every entry in the map was expired.
        let now = Instant::now();
        let mut inner = Inner {
            accounts: HashMap::new(),
            sessions: HashMap::new(),
            rotated_sessions: HashMap::new(),
            // Claim a sweep just happened, so only the capacity clause can
            // trigger reclamation.
            sessions_swept_at: now,
        };
        for index in 0..MAX_ACTIVE_SESSIONS {
            let mut token_hash = [0u8; 32];
            token_hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
            inner
                .sessions
                .insert(token_hash, expired_session("full@example.com", now));
        }
        assert_eq!(inner.sessions.len(), MAX_ACTIVE_SESSIONS);

        retain_live_sessions(&mut inner, now + Duration::from_millis(1));
        assert!(
            inner.sessions.is_empty(),
            "a full map of expired sessions was not reclaimed"
        );
    }

    #[test]
    fn liveness_accessors_reject_expired_records_without_a_sweep() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut inner = Inner {
            accounts: HashMap::new(),
            sessions: HashMap::new(),
            rotated_sessions: HashMap::new(),
            sessions_swept_at: now,
        };
        let successor_hash = [1u8; 32];
        let predecessor_hash = [2u8; 32];
        inner
            .sessions
            .insert(successor_hash, expired_session("stale@example.com", now));
        inner.rotated_sessions.insert(
            predecessor_hash,
            RotatedSession {
                email: "stale@example.com".to_string(),
                family_id: [0u8; 16],
                successor_hash,
                // Grace itself has not lapsed; the successor behind it has.
                expires_at: later + Duration::from_secs(60),
            },
        );

        // The records are still in the maps: nothing has been reclaimed. They
        // must be refused anyway, or authentication would depend on the sweep.
        assert!(live_session(&inner, &successor_hash, later).is_none());
        assert!(live_predecessor(&inner, &predecessor_hash, later).is_none());
    }

    #[test]
    fn decoy_kdf_follows_the_local_population_not_a_constant() {
        fn account(kdf: KdfParams) -> AccountRecord {
            AccountRecord {
                salt: String::new(),
                kdf,
                wrapped_vault_key: EncryptedBlob {
                    v: 1,
                    nonce: String::new(),
                    ct: String::new(),
                },
                auth_hash: String::new(),
                email_verified_at: None,
                items: HashMap::new(),
                item_bytes: HashMap::new(),
                manifest: None,
                manifest_bytes: 0,
                stored_bytes: 0,
                vault_revision: 0,
            }
        }

        // An empty deployment falls back to the registration defaults.
        assert_eq!(modal_kdf(&HashMap::new()), KdfParams::default());

        // A deployment whose accounts were registered with other parameters
        // gets decoys that match them. Announcing the defaults there marked
        // every decoy as a decoy.
        let hardened = KdfParams {
            mem_kib: 256 * 1024,
            iterations: 4,
            parallelism: 2,
        };
        let mut accounts = HashMap::new();
        accounts.insert("a@example.com".to_string(), account(hardened));
        accounts.insert("b@example.com".to_string(), account(hardened));
        accounts.insert("c@example.com".to_string(), account(KdfParams::default()));
        assert_eq!(modal_kdf(&accounts), hardened);

        let seed = [3u8; 32];
        let decoy = prelogin_decoy(&seed, modal_kdf(&accounts), "nobody@example.com");
        assert_eq!(decoy.kdf, hardened);
        // Still deterministic per email, so a decoy never moves under an
        // observer who asks twice.
        let repeat = prelogin_decoy(&seed, modal_kdf(&accounts), "nobody@example.com");
        assert_eq!(decoy.salt, repeat.salt);
        assert_eq!(decoy.wrapped_vault_key.ct, repeat.wrapped_vault_key.ct);
    }

    #[test]
    fn standing_allowances_do_not_share_a_table_with_per_minute_limits() {
        // A table's sweep drops entries idle for longer than the window it is
        // called with. A per-minute sweep over a day-long bucket would refill
        // every standing allowance for free, so they must not share a table.
        let mut mixed = HashMap::new();
        let start = Instant::now();
        let day = Duration::from_secs(24 * 60 * 60);
        let minute = Duration::from_secs(60);
        assert!(rate_limit_map_at(&mut mixed, 8, day, "pair", "day", 2, start).is_ok());
        // Two hours later a per-minute limit sweeps the same table.
        let later = start + Duration::from_secs(2 * 60 * 60);
        for index in 0..8 {
            let _ = rate_limit_map_at(
                &mut mixed,
                8,
                minute,
                &format!("filler-{index}"),
                "minute",
                2,
                later,
            );
        }
        assert!(
            !mixed.contains_key("day\0pair"),
            "this test no longer demonstrates the hazard it guards against"
        );
    }

    #[test]
    fn a_full_rate_table_evicts_its_stalest_bucket_instead_of_refusing_service() {
        let mut rate = HashMap::new();
        let window = Duration::from_secs(60);
        let start = Instant::now();

        let admit = |rate: &mut HashMap<String, RateState>, subject: &str, at: Instant| {
            rate_limit_map_at(rate, 2, window, subject, "b", 5, at).is_ok()
        };

        // Two live buckets fill the table.
        assert!(admit(&mut rate, "first", start));
        assert!(admit(&mut rate, "second", start + Duration::from_secs(1)));

        // A third subject is admitted; the least recently used bucket goes.
        assert!(admit(&mut rate, "third", start + Duration::from_secs(2)));
        assert_eq!(rate.len(), 2);
        assert!(!rate.contains_key("b\0first"));
        assert!(rate.contains_key("b\0second"));
        assert!(rate.contains_key("b\0third"));

        // Enforcement survives eviction for the buckets that remain.
        let now = start + Duration::from_secs(2);
        for _ in 0..4 {
            assert!(admit(&mut rate, "third", now));
        }
        assert!(!admit(&mut rate, "third", now));
    }

    #[test]
    fn trusted_client_address_is_single_and_canonical() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_static("::ffff:192.0.2.44"),
        );
        assert_eq!(
            canonical_client_ip(&headers),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)))
        );

        headers.append(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_static("198.51.100.8"),
        );
        assert_eq!(canonical_client_ip(&headers), None);

        let mut chained = HeaderMap::new();
        chained.insert(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_static("192.0.2.44, 198.51.100.8"),
        );
        assert_eq!(canonical_client_ip(&chained), None);
    }

    #[test]
    fn vault_etags_are_stable_and_scoped_to_account_and_revision() {
        let seed = [7u8; 32];
        let first = vault_etag(&seed, "alice@example.com", 4);
        assert_eq!(first, vault_etag(&seed, "alice@example.com", 4));
        assert_ne!(first, vault_etag(&seed, "alice@example.com", 5));
        assert_ne!(first, vault_etag(&seed, "bob@example.com", 4));
        assert_ne!(first, vault_etag(&[8u8; 32], "alice@example.com", 4));
        assert_eq!(first.len(), 68);
    }

    #[test]
    fn account_ids_fold_ascii_case_only_after_structural_validation() {
        assert_eq!(
            canonical_account_id("Alice+Vault@Example.COM")
                .ok()
                .unwrap()
                .as_str(),
            "alice+vault@example.com"
        );
        for invalid in [
            " alice@example.com",
            "alice @example.com",
            "álîçé@example.com",
        ] {
            assert!(
                canonical_account_id(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn schema_v5_canonicalizes_every_account_reference() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_v0_to_v1(&mut conn).unwrap();
        migrate_v1_to_v2(&mut conn).unwrap();
        migrate_v2_to_v3(&mut conn).unwrap();
        migrate_v3_to_v4(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO accounts(
               email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision,email_verified_at
             ) VALUES('Alice@Example.COM','salt','{}','{}','hash',7,1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO items(email,id,blob)
             VALUES('Alice@Example.COM','item','{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO manifests(email,blob) VALUES('Alice@Example.COM','{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO send_directory(email,bastion_id,public,created_at)
             VALUES('Alice@Example.COM','recipient','{}',1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO send_inbox(recipient_id,message_id,blob,created_at,expires_at)
             VALUES('recipient','message','{}',1,NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO registration_challenges(
               email,token_hash,expires_at,resend_after,verified_at,created_at
             ) VALUES('Proof@Example.COM',?1,100,50,60,1)",
            params![[9u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO registration_challenges(
               email,token_hash,expires_at,resend_after,verified_at,created_at
             ) VALUES('ALICE@EXAMPLE.COM',?1,100,50,60,1)",
            params![[8u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mail_outbox(
               id,account_email,challenge_email,recipient,subject,text_body,state,
               attempts,available_at,created_at
             ) VALUES(
               '00112233445566778899aabbccddeeff','Alice@Example.COM',NULL,
               'Alice@Example.COM','Subject','Body','pending',0,1,1
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mail_outbox(
               id,account_email,challenge_email,recipient,subject,text_body,state,
               attempts,available_at,created_at
             ) VALUES(
               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',NULL,'ALICE@EXAMPLE.COM',
               'ALICE@EXAMPLE.COM','Obsolete','Body','pending',0,1,1
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mail_outbox(
               id,account_email,challenge_email,recipient,subject,text_body,state,
               attempts,available_at,created_at
             ) VALUES(
               'ffeeddccbbaa99887766554433221100',NULL,'Proof@Example.COM',
               'Proof@Example.COM','Subject','Body','pending',0,1,1
             )",
            [],
        )
        .unwrap();

        migrate_v4_to_v5(&mut conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);
        for (table, column, expected) in [
            ("accounts", "email", "alice@example.com"),
            ("items", "email", "alice@example.com"),
            ("manifests", "email", "alice@example.com"),
            ("send_directory", "email", "alice@example.com"),
            ("registration_challenges", "email", "proof@example.com"),
        ] {
            let actual: String = conn
                .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(actual, expected, "{table}.{column}");
        }
        let outbox: Vec<(Option<String>, Option<String>, String)> = conn
            .prepare(
                "SELECT account_email,challenge_email,recipient
                   FROM mail_outbox ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            outbox,
            vec![
                (
                    Some("alice@example.com".to_string()),
                    None,
                    "alice@example.com".to_string()
                ),
                (
                    None,
                    Some("proof@example.com".to_string()),
                    "proof@example.com".to_string()
                ),
            ]
        );
        let has_violation = {
            let mut statement = conn.prepare("PRAGMA foreign_key_check").unwrap();
            let has_violation = statement.query([]).unwrap().next().unwrap().is_some();
            has_violation
        };
        assert!(!has_violation);
        assert!(conn
            .execute(
                "INSERT INTO accounts(
                   email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision,email_verified_at
                 ) VALUES('Upper@Example.COM','salt','{}','{}','hash',0,1)",
                [],
            )
            .is_err());
    }

    #[test]
    fn schema_v5_refuses_case_collisions_without_modifying_v4() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_v0_to_v1(&mut conn).unwrap();
        migrate_v1_to_v2(&mut conn).unwrap();
        migrate_v2_to_v3(&mut conn).unwrap();
        migrate_v3_to_v4(&mut conn).unwrap();
        for email in ["Alice@Example.COM", "alice@example.com"] {
            conn.execute(
                "INSERT INTO accounts(
                   email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision,email_verified_at
                 ) VALUES(?1,'salt','{}','{}','hash',0,1)",
                [email],
            )
            .unwrap();
        }

        assert!(migrate_v4_to_v5(&mut conn).is_err());
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let accounts: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
            .unwrap();
        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4);
        assert_eq!(accounts, 2);
        assert_eq!(foreign_keys, 1);

        conn.execute("DELETE FROM accounts WHERE email='Alice@Example.COM'", [])
            .unwrap();
        for (email, token) in [
            ("Proof@Example.COM", [1u8; 32]),
            ("proof@example.com", [2u8; 32]),
        ] {
            conn.execute(
                "INSERT INTO registration_challenges(
                   email,token_hash,expires_at,resend_after,verified_at,created_at
                 ) VALUES(?1,?2,100,50,NULL,1)",
                params![email, token.as_slice()],
            )
            .unwrap();
        }
        assert!(migrate_v4_to_v5(&mut conn).is_err());
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4);
    }

    #[test]
    fn if_none_match_parser_rejects_ambiguous_or_malformed_values() {
        let current = "\"current\"";
        let mut headers = HeaderMap::new();
        headers.append(header::IF_NONE_MATCH, HeaderValue::from_static("\"stale\""));
        headers.append(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"current\""),
        );
        assert!(matches!(if_none_match_matches(&headers, current), Ok(true)));

        for value in [
            "",
            "current",
            "\"unterminated",
            "*, \"current\"",
            "\"valid\",",
            "w/\"current\"",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::IF_NONE_MATCH,
                HeaderValue::from_str(value).expect("test header value"),
            );
            assert!(
                if_none_match_matches(&headers, current).is_err(),
                "accepted {value:?}"
            );
        }
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

        for (name, host, proto, source, expected) in [
            (
                "missing host",
                None,
                Some("https"),
                Some("192.0.2.1"),
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "wrong host",
                Some("attacker.example"),
                Some("https"),
                Some("192.0.2.1"),
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "wrong port",
                Some("vault.example.com:444"),
                Some("https"),
                Some("192.0.2.1"),
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "missing proto",
                Some("vault.example.com"),
                None,
                Some("192.0.2.1"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "plaintext proto",
                Some("vault.example.com"),
                Some("http"),
                Some("192.0.2.1"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "proto forwarding chain",
                Some("vault.example.com"),
                Some("https,http"),
                Some("192.0.2.1"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "missing client source",
                Some("vault.example.com"),
                Some("https"),
                None,
                StatusCode::BAD_REQUEST,
            ),
            (
                "client forwarding chain",
                Some("vault.example.com"),
                Some("https"),
                Some("192.0.2.1, 198.51.100.2"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "malformed client source",
                Some("vault.example.com"),
                Some("https"),
                Some("not-an-ip"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "valid ingress",
                Some("VAULT.EXAMPLE.COM"),
                Some("https"),
                Some("192.0.2.1"),
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
            if let Some(source) = source {
                request = request.header(FORWARDED_FOR_HEADER, source);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{name}");
            assert_eq!(
                response.headers()[header::STRICT_TRANSPORT_SECURITY],
                "max-age=31536000; includeSubDomains; preload",
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

        for duplicate in [
            header::HOST.as_str(),
            FORWARDED_PROTO_HEADER,
            FORWARDED_FOR_HEADER,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/accounts/nobody@example.com/prelogin")
                        .header(header::HOST, "vault.example.com")
                        .header(FORWARDED_PROTO_HEADER, "https")
                        .header(FORWARDED_FOR_HEADER, "192.0.2.1")
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

    #[tokio::test]
    async fn trusted_source_limit_survives_account_identifier_rotation() {
        let app = build_with_transport(
            DEFAULT_TOKEN_TTL,
            ":memory:",
            MAX_CONCURRENT_AUTH,
            Some(TransportPolicy::parse("https://vault.example.com").unwrap()),
            None,
        );

        let request = |email: &str, source: &str| {
            Request::builder()
                .uri(format!("/v1/accounts/{email}/prelogin"))
                .header(header::HOST, "vault.example.com")
                .header(FORWARDED_PROTO_HEADER, "https")
                .header(FORWARDED_FOR_HEADER, source)
                .body(Body::empty())
                .unwrap()
        };

        for attempt in 0..MAX_PRELOGINS_PER_SOURCE_PER_MIN {
            let response = app
                .clone()
                .oneshot(request(
                    &format!("rotating-{attempt}@example.com"),
                    "192.0.2.10",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "attempt {attempt}");
        }
        let response = app
            .clone()
            .oneshot(request("blocked@example.com", "192.0.2.10"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // The source bucket prevents one address from consuming the global
        // allowance. A distinct trusted source can still use that allowance.
        let response = app
            .oneshot(request("independent@example.com", "198.51.100.20"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn production_exposes_only_atomic_vault_mutations() {
        let app = build_with_transport(
            DEFAULT_TOKEN_TTL,
            ":memory:",
            MAX_CONCURRENT_AUTH,
            Some(TransportPolicy::parse("https://vault.example.com").unwrap()),
            None,
        );

        for path in [
            "/vault/items/item-9",
            "/v1/vault/items/item-9",
            "/vault/manifest",
            "/v1/vault/manifest",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(path)
                        .header(header::HOST, "vault.example.com")
                        .header(FORWARDED_PROTO_HEADER, "https")
                        .header(FORWARDED_FOR_HEADER, "192.0.2.1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "deprecated mutation route remained registered at {path}"
            );
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/vault/transaction")
                    .header(header::HOST, "vault.example.com")
                    .header(FORWARDED_PROTO_HEADER, "https")
                    .header(FORWARDED_FOR_HEADER, "192.0.2.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
    async fn delayed_mutation_sheds_new_storage_work_then_recovers() {
        let (db, _, _) = Db::open_with_limits(":memory:", 1, Duration::from_millis(10));
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = completed.clone();
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);

        // The mutation overruns its response deadline, then commits. Awaiting
        // it keeps cache/storage ordering intact, while the transient overload
        // state rejects new work instead of building a queue behind it.
        let slow_db = db.clone();
        let mutation = tokio::spawn(async move {
            slow_db
                .call_mutation(move |conn| {
                    entered_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    conn.execute("CREATE TABLE delayed(value INTEGER)", [])?;
                    worker_completed.store(true, Ordering::Release);
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
        tokio::time::timeout(Duration::from_secs(1), async {
            while db.is_accepting_work() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("slow mutation never withdrew storage admission");

        assert!(matches!(
            db.call(|_| Ok(())).await,
            Err(DbError::ResponseTimeout)
        ));
        assert!(matches!(db.ready().await, Err(DbError::ResponseTimeout)));

        release_sender.send(()).unwrap();
        mutation.await.unwrap().unwrap();
        assert!(completed.load(Ordering::Acquire));
        assert!(db.is_available());
        assert!(db.is_accepting_work());
        assert!(db.ready().await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_slow_mutation_recovers_without_false_quarantine() {
        let (db, _, _) = Db::open_with_limits(":memory:", 1, Duration::from_millis(10));

        // The final SQLite error is an unambiguous rollback: the cache never
        // advances, so permanent quarantine would create a client-triggerable
        // restart-only outage without protecting consistency.
        assert!(db
            .call_mutation(move |conn| {
                thread::sleep(Duration::from_millis(50));
                conn.execute("INSERT INTO table_that_does_not_exist VALUES(1)", [])?;
                Ok(())
            })
            .await
            .is_err());
        assert!(db.is_available());
        assert!(db.is_accepting_work());
        assert!(db.ready().await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_slow_read_reports_unavailable_without_quarantining_the_instance() {
        let (db, _, _) = Db::open_with_limits(":memory:", 4, Duration::from_millis(10));

        // Reads mutate nothing, so a timed-out read is a load signal. Treating
        // it as a fault handed anyone who could saturate the storage owner —
        // including an unauthenticated /readyz flood — a permanent outage.
        assert!(matches!(
            db.call(|_| {
                thread::sleep(Duration::from_millis(50));
                Ok(())
            })
            .await,
            Err(DbError::ResponseTimeout)
        ));
        assert!(db.is_available());
        // Once the storage owner drains the abandoned job, readiness recovers
        // on its own — no restart, which is the whole point.
        tokio::time::timeout(Duration::from_secs(1), async {
            while db.ready().await.is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("readiness never recovered");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn readiness_is_served_from_a_short_lived_cache() {
        let (db, _, _) = Db::open_with_limits(":memory:", 4, Duration::from_secs(5));
        assert!(db.ready().await.is_ok());

        // With the storage owner parked, an uncached probe would have to queue
        // behind it. Answering from the cache is what keeps an unauthenticated
        // probe flood from costing one storage command each.
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let parked_db = db.clone();
        let parked = tokio::spawn(async move {
            parked_db
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

        tokio::time::timeout(Duration::from_millis(100), db.ready())
            .await
            .expect("readiness waited on the parked storage owner")
            .unwrap();

        release_sender.send(()).unwrap();
        parked.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_uncached_readiness_has_one_storage_probe_in_flight() {
        let (db, _, _) = Db::open_with_limits(":memory:", 8, Duration::from_secs(5));
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let parked_db = db.clone();
        let parked = tokio::spawn(async move {
            parked_db
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

        let probing_db = db.clone();
        let first_probe = tokio::spawn(async move { probing_db.ready().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while db.sender.capacity() != 7 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first readiness probe was not queued");

        for _ in 0..32 {
            assert!(matches!(db.ready().await, Err(DbError::QueueFull)));
            assert_eq!(
                db.sender.capacity(),
                7,
                "concurrent readiness probe reached the SQLite queue"
            );
        }

        release_sender.send(()).unwrap();
        parked.await.unwrap().unwrap();
        first_probe.await.unwrap().unwrap();
        assert!(db.ready().await.is_ok());
    }

    #[test]
    fn honeypot_lures_never_shadow_a_real_route() {
        // `build` panics on a duplicate route, so constructing the router is
        // itself the assertion that no lure sits on a path a client uses.
        let _ = build(DEFAULT_TOKEN_TTL, ":memory:", MAX_CONCURRENT_AUTH);
        for path in HONEYPOT_PATHS {
            assert!(is_honeypot_path(path), "{path} not classified as a lure");
            assert!(
                is_honeypot_path(&format!("/v1{path}")),
                "{path} not classified as a lure under /v1"
            );
            // A lure must be a fixed, closed-set path: keeping it verbatim in
            // the log adds no attacker-controlled cardinality.
            assert_eq!(redacted_path(path), path);
        }
        for real in ["/config", "/health", "/vault", "/sessions", "/accounts"] {
            assert!(!is_honeypot_path(real), "{real} classified as a lure");
        }
    }

    #[tokio::test]
    async fn honeypot_answers_a_constant_body_that_reflects_nothing() {
        let app = build(DEFAULT_TOKEN_TTL, ":memory:", MAX_CONCURRENT_AUTH);
        let mut bodies = HashSet::new();
        for path in ["/.env", "/v1/.env", "/admin", "/wp-login.php"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            bodies.insert(body.to_vec());
        }
        assert_eq!(bodies.len(), 1, "lure body varies between paths");
        let body = String::from_utf8(bodies.into_iter().next().unwrap()).unwrap();
        assert!(body.contains("good try"));
        assert!(body.contains("/.well-known/security.txt"));
    }

    #[tokio::test]
    async fn security_txt_points_at_the_real_reporting_channel() {
        let app = build(DEFAULT_TOKEN_TTL, ":memory:", MAX_CONCURRENT_AUTH);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/security.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Contact: https://github.com/"));
        assert!(body.contains("Policy: https://github.com/"));
        // Expires is mandatory in RFC 9116 and must be in the future.
        assert!(body.contains("Expires: 20"));
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // Leap day, and the last second of a leap year.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_735_689_599), "2024-12-31T23:59:59Z");
    }

    #[test]
    fn security_events_are_counted_by_class() {
        let (event, total) = security_event(StatusCode::UNAUTHORIZED, "/vault").unwrap();
        assert_eq!(event, "auth_rejected");
        // Other request tests run in parallel and share the process-level
        // counters, so assert monotonic progress without an exact racy delta.
        assert!(total > 0);

        assert_eq!(
            security_event(StatusCode::NOT_FOUND, "/.env").unwrap().0,
            "honeypot"
        );
        assert_eq!(
            security_event(StatusCode::MISDIRECTED_REQUEST, "/.env")
                .unwrap()
                .0,
            "wrong_public_host"
        );
        assert_eq!(
            security_event(StatusCode::TOO_MANY_REQUESTS, "/sessions")
                .unwrap()
                .0,
            "rate_limited"
        );
        assert_eq!(
            security_event(StatusCode::NOT_FOUND, "/{unmatched}")
                .unwrap()
                .0,
            "unmatched_path"
        );
        // Ordinary outcomes stay at info and are not counted.
        assert!(security_event(StatusCode::OK, "/vault").is_none());
        assert!(security_event(StatusCode::CONFLICT, "/accounts").is_none());
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
        // Unknown paths are attacker-controlled and may contain accidental
        // secrets; retain neither their contents nor their cardinality.
        assert_eq!(
            redacted_path("/reset/verification-token-123"),
            "/{unmatched}"
        );
        assert_eq!(
            redacted_path("/v1/reset/verification-token-123"),
            "/v1/{unmatched}"
        );
        assert_eq!(redacted_path("/v1evil/token"), "/{unmatched}");
    }

    #[test]
    fn persistence_validation_errors_do_not_disclose_account_ids() {
        let sensitive_account = "customer+incident@example.com";
        let error = validate_persisted_credentials(
            sensitive_account,
            "invalid",
            KdfParams {
                mem_kib: 0,
                iterations: 0,
                parallelism: 0,
            },
            &EncryptedBlob {
                v: 0,
                nonce: String::new(),
                ct: String::new(),
            },
            "invalid",
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid persisted account credentials");
        assert!(!error.to_string().contains(sensitive_account));
    }
}

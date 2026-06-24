//! Serveur de synchronisation **zero-knowledge**.
//!
//! Il ne voit jamais le mot de passe maître, la Secret Key, ni un item en clair.
//! Il stocke uniquement :
//! - les données d'inscription publiques (`salt`, `kdf`, clé de coffre enveloppée) ;
//! - un **hash lent Argon2id** du secret d'authentification (jamais le secret nu) ;
//! - les items et le manifest, sous forme de [`EncryptedBlob`] opaques.
//!
//! Le stockage est en mémoire (MVP) ; une couche persistante (SQLite…) pourra
//! s'y substituer sans changer l'API HTTP.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crypto_core::{EncryptedBlob, KdfParams, Registration};

/// Durée de vie d'un jeton de session par défaut (30 min).
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// Taille maximale d'un corps de requête (1 Mio) — garde-fou anti-DoS mémoire.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Construit le routeur avec la TTL de session par défaut.
///
/// ⚠️ NON-PRODUCTION : ce serveur MVP n'a PAS de TLS, CORS, rate-limiting,
/// quotas de stockage, ni persistance. Ces contrôles doivent être ajoutés
/// (et testés) avant tout déploiement réel.
pub fn app() -> Router {
    app_with_ttl(DEFAULT_TOKEN_TTL)
}

/// Variante avec TTL explicite (utile pour tester l'expiration des jetons).
pub fn app_with_ttl(token_ttl: Duration) -> Router {
    let state = AppState::new(token_ttl);
    Router::new()
        .route("/health", get(health))
        .route("/accounts", post(create_account))
        .route("/accounts/:email/prelogin", get(prelogin))
        .route("/sessions", post(create_session).delete(delete_session))
        .route("/vault", get(get_vault))
        .route("/vault/items/:id", put(put_item).delete(delete_item))
        .route("/vault/manifest", put(put_manifest))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

// ─── État partagé ───

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<Inner>>,
    token_ttl: Duration,
}

#[derive(Default)]
struct Inner {
    accounts: HashMap<String, AccountRecord>, // email -> compte
    sessions: HashMap<String, Session>,       // jeton -> session
}

/// Session active : propriétaire du jeton et instant d'expiration.
struct Session {
    email: String,
    expires_at: Instant,
}

/// Tout ce que le serveur retient d'un compte. Rien ici n'est déchiffrable.
struct AccountRecord {
    salt: String,
    kdf: KdfParams,
    wrapped_vault_key: EncryptedBlob,
    /// Hash Argon2id (PHC) du secret d'authentification.
    auth_hash: String,
    items: HashMap<String, EncryptedBlob>,
    manifest: Option<EncryptedBlob>,
}

impl AppState {
    fn new(token_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            token_ttl,
        }
    }

    /// Verrou en lecture, en **récupérant** un éventuel empoisonnement : le
    /// panic d'un autre handler ne doit pas mettre tout le serveur en DoS.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Idem en écriture.
    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

// ─── Erreurs HTTP (messages volontairement avares) ───

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
    /// Secret d'authentification base64 dérivé côté client.
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
    // Hash lent sur un thread bloquant dédié (pas de starvation du runtime async).
    let secret = req.registration.auth_secret.expose_b64().to_string();
    let auth_hash = tokio::task::spawn_blocking(move || hash_secret(&secret))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "join error"))?
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "hash failure"))?;

    let mut inner = st.write();
    if inner.accounts.contains_key(&req.email) {
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
    // On copie le hash puis on relâche le verrou avant la vérification lente.
    let phc = st
        .read()
        .accounts
        .get(&req.email)
        .map(|a| a.auth_hash.clone());
    // Même réponse pour « compte inconnu » et « mauvais secret ».
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
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
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
    acc.items.remove(&id);
    Ok(StatusCode::NO_CONTENT)
}

async fn put_manifest(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BlobBody>,
) -> Result<StatusCode, ApiError> {
    let email = require_auth(&st, &headers)?;
    let mut inner = st.write();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    acc.manifest = Some(body.blob);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Helpers ───

/// Révoque la session courante (déconnexion).
async fn delete_session(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let token = bearer_token(&headers)?.to_string();
    st.write().sessions.remove(&token);
    Ok(StatusCode::NO_CONTENT)
}

/// Extrait le jeton « Authorization: Bearer … ».
fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))
}

/// Valide le jeton (existence + non-expiration) et renvoie l'email. Évince un
/// jeton expiré au passage.
fn require_auth(st: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = bearer_token(headers)?.to_string();
    let mut inner = st.write();
    let email = match inner.sessions.get(&token) {
        Some(s) if Instant::now() < s.expires_at => Some(s.email.clone()),
        Some(_) => None, // expiré
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

/// Hash lent Argon2id (PHC) du secret d'authentification.
fn hash_secret(secret: &str) -> Result<String, ()> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ())
}

/// Vérifie un secret contre un hash PHC, en temps constant (via `argon2`).
fn verify_secret(secret: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Jeton de session aléatoire de 256 bits, encodé hex.
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    data_encoding::HEXLOWER.encode(&bytes)
}

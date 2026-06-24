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
use std::sync::{Arc, RwLock};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crypto_core::{EncryptedBlob, KdfParams, Registration};

/// Construit le routeur de l'application (utilisable tel quel dans les tests).
pub fn app() -> Router {
    let state = AppState::new();
    Router::new()
        .route("/health", get(health))
        .route("/accounts", post(create_account))
        .route("/accounts/:email/prelogin", get(prelogin))
        .route("/sessions", post(create_session))
        .route("/vault", get(get_vault))
        .route("/vault/items/:id", put(put_item).delete(delete_item))
        .route("/vault/manifest", put(put_manifest))
        .with_state(state)
}

// ─── État partagé ───

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    accounts: HashMap<String, AccountRecord>, // email -> compte
    sessions: HashMap<String, String>,        // jeton -> email
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
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
        }
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
    // Hash lent calculé HORS du verrou (CPU), pour ne pas bloquer les lecteurs.
    let auth_hash = hash_secret(req.registration.auth_secret.expose_b64())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "hash failure"))?;

    let mut inner = st.inner.write().unwrap();
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
    let inner = st.inner.read().unwrap();
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
        .inner
        .read()
        .unwrap()
        .accounts
        .get(&req.email)
        .map(|a| a.auth_hash.clone());
    // Même réponse pour « compte inconnu » et « mauvais secret ».
    let phc = phc.ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    if !verify_secret(&req.auth_secret, &phc) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let token = new_token();
    st.inner
        .write()
        .unwrap()
        .sessions
        .insert(token.clone(), req.email);
    Ok(Json(LoginResponse { token }))
}

async fn get_vault(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultResponse>, ApiError> {
    let email = require_auth(&st, &headers)?;
    let inner = st.inner.read().unwrap();
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
    let mut inner = st.inner.write().unwrap();
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
    let mut inner = st.inner.write().unwrap();
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
    let mut inner = st.inner.write().unwrap();
    let acc = inner
        .accounts
        .get_mut(&email)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))?;
    acc.manifest = Some(body.blob);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Helpers ───

/// Extrait et valide le jeton « Authorization: Bearer … ». Renvoie l'email.
fn require_auth(st: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    st.inner
        .read()
        .unwrap()
        .sessions
        .get(token)
        .cloned()
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token"))
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

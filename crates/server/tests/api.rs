//! Tests d'intégration de l'API du serveur (via `tower::oneshot`, sans réseau).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use crypto_core::kdf::KdfParams;
use crypto_core::Vault;

fn fast_kdf() -> KdfParams {
    KdfParams {
        mem_kib: KdfParams::MIN_MEM_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: KdfParams::MIN_PARALLELISM,
    }
}

/// Envoie une requête et renvoie (statut, corps JSON éventuel).
async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let request = match body {
        Some(j) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&j).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

#[tokio::test]
async fn full_account_and_vault_flow() {
    let app = server::app();
    let (vault, reg, _sk) = Vault::register_with(b"masterpw", fast_kdf()).unwrap();
    let auth_secret = reg.auth_secret.expose_b64().to_string();
    let reg_value = serde_json::to_value(&reg).unwrap();
    let email = "alice@example.com";

    // Inscription.
    let (s, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": reg_value })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Doublon → conflit.
    let (s, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": reg_value })),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Prelogin : renvoie le sel public, pas de secret.
    let (s, body) = send(
        &app,
        "GET",
        &format!("/accounts/{email}/prelogin"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["salt"], reg.salt);
    assert!(body.get("auth_secret").is_none());
    assert!(body.get("auth_hash").is_none());

    // Login avec mauvais secret → 401.
    let (s, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": "not-the-secret" })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Login correct → jeton.
    let (s, body) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let token = body["token"].as_str().unwrap().to_string();

    // Accès au coffre sans jeton → 401.
    let (s, _) = send(&app, "GET", "/vault", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Stockage d'un item chiffré.
    let blob = serde_json::to_value(vault.encrypt_item(b"hunter2", "github.com").unwrap()).unwrap();
    let (s, _) = send(
        &app,
        "PUT",
        "/vault/items/github.com",
        Some(&token),
        Some(json!({ "blob": blob })),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Récupération : l'item chiffré est là, et déchiffrable côté client.
    let (s, body) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    let stored: crypto_core::EncryptedBlob =
        serde_json::from_value(body["items"]["github.com"].clone()).unwrap();
    let plain = vault.decrypt_item(&stored, "github.com").unwrap();
    assert_eq!(plain.as_slice(), b"hunter2");

    // Suppression.
    let (s, _) = send(
        &app,
        "DELETE",
        "/vault/items/github.com",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, body) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert!(body["items"].get("github.com").is_none());
}

#[tokio::test]
async fn prelogin_unknown_account_is_404() {
    let app = server::app();
    let (s, _) = send(
        &app,
        "GET",
        "/accounts/ghost@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bad_token_is_rejected() {
    let app = server::app();
    let (s, _) = send(&app, "GET", "/vault", Some("deadbeef"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_ok() {
    let app = server::app();
    let (s, _) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::OK);
}

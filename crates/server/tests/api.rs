//! Integration tests for the server API (via `tower::oneshot`, no network).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
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

/// Sends a request and returns (status, optional JSON body).
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
    let app = server::app_in_memory();
    let (vault, reg, _sk) = Vault::register_with(b"masterpw", fast_kdf()).unwrap();
    let auth_secret = reg.auth_secret.expose_b64().to_string();
    let reg_value = serde_json::to_value(&reg).unwrap();
    let email = "alice@example.com";

    // Signup.
    let (s, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": reg_value })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Duplicate -> conflict.
    let (s, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": reg_value })),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Prelogin: returns the public salt, no secret.
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

    // Login with a wrong secret -> 401.
    let (s, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": B64.encode([0u8; 32]) })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Correct login -> token.
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

    // Vault access without a token -> 401.
    let (s, _) = send(&app, "GET", "/vault", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Storing an encrypted item.
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

    // Retrieval: the encrypted item is there, and decryptable on the client side.
    let (s, body) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    let stored: crypto_core::EncryptedBlob =
        serde_json::from_value(body["items"]["github.com"].clone()).unwrap();
    let plain = vault.decrypt_item(&stored, "github.com").unwrap();
    assert_eq!(plain.as_slice(), b"hunter2");

    // Deletion.
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
async fn rejects_malformed_account_identifiers() {
    let app = server::app_in_memory();
    let (_, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let registration = serde_json::to_value(&reg).unwrap();
    let invalid = [
        "",
        "missing-at-sign",
        " leading@example.com",
        "trailing@example.com ",
        "two@@example.com",
        "non-ascii-é@example.com",
    ];

    for email in invalid {
        let (status, _) = send(
            &app,
            "POST",
            "/accounts",
            None,
            Some(json!({ "email": email, "registration": registration })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {email:?}");
    }
}

#[tokio::test]
async fn rejects_malformed_registration_before_storage() {
    let app = server::app_in_memory();
    let (_, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let valid = serde_json::to_value(&reg).unwrap();
    let mut invalid = Vec::new();

    let mut wrong_version = valid.clone();
    wrong_version["version"] = json!(2);
    invalid.push(wrong_version);

    let mut bad_salt = valid.clone();
    bad_salt["salt"] = json!("not-base64");
    invalid.push(bad_salt);

    let mut weak_kdf = valid.clone();
    weak_kdf["kdf"]["mem_kib"] = json!(1);
    invalid.push(weak_kdf);

    let mut bad_auth_secret = valid.clone();
    bad_auth_secret["auth_secret"] = json!("short");
    invalid.push(bad_auth_secret);

    let mut bad_wrapped_nonce = valid;
    bad_wrapped_nonce["wrapped_vault_key"]["nonce"] = json!("short");
    invalid.push(bad_wrapped_nonce);

    for (index, registration) in invalid.into_iter().enumerate() {
        let (status, _) = send(
            &app,
            "POST",
            "/accounts",
            None,
            Some(json!({
                "email": format!("invalid-registration-{index}@example.com"),
                "registration": registration
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted case {index}");
    }
}

#[tokio::test]
async fn rejects_malformed_login_credentials_without_hashing() {
    let app = server::app_in_memory();
    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "missing@example.com",
            "auth_secret": "not-a-fixed-width-secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_authentication_work_when_capacity_is_exhausted() {
    let app = server::app_in_memory_with_auth_limit(0);
    let (_, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "busy@example.com",
            "registration": serde_json::to_value(&reg).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let (status, _) = send(
        &app,
        "GET",
        "/accounts/busy@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn caps_active_sessions_per_account_by_revoking_the_oldest() {
    let app = server::app_in_memory();
    let (_, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth = reg.auth_secret.expose_b64().to_string();
    let email = "session-cap@example.com";
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": email,
            "registration": serde_json::to_value(&reg).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let mut tokens = Vec::new();
    for _ in 0..9 {
        let (status, login) = send(
            &app,
            "POST",
            "/sessions",
            None,
            Some(json!({ "email": email, "auth_secret": auth })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        tokens.push(login["token"].as_str().unwrap().to_string());
    }

    let (status, _) = send(&app, "GET", "/vault", Some(&tokens[0]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        "GET",
        "/vault",
        tokens.last().map(String::as_str),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn concurrent_registration_never_replaces_account_credentials() {
    let app = server::app_in_memory();
    let email = "registration-race@example.com";
    let (_, first, _) = Vault::register_with(b"first", fast_kdf()).unwrap();
    let (_, second, _) = Vault::register_with(b"second", fast_kdf()).unwrap();
    let first_auth = first.auth_secret.expose_b64().to_string();
    let second_auth = second.auth_secret.expose_b64().to_string();
    let first_body =
        json!({ "email": email, "registration": serde_json::to_value(&first).unwrap() });
    let second_body =
        json!({ "email": email, "registration": serde_json::to_value(&second).unwrap() });

    let (first_result, second_result) = tokio::join!(
        send(&app, "POST", "/accounts", None, Some(first_body)),
        send(&app, "POST", "/accounts", None, Some(second_body)),
    );
    let statuses = [first_result.0, second_result.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1
    );

    let login = |auth_secret: String| {
        send(
            &app,
            "POST",
            "/sessions",
            None,
            Some(json!({ "email": email, "auth_secret": auth_secret })),
        )
    };
    let (first_login, second_login) = tokio::join!(login(first_auth), login(second_auth));
    assert_eq!(
        [first_login.0, second_login.0]
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1,
        "exactly the winning registration must remain valid"
    );
}

/// Registers an account and returns a valid session token.
async fn registered_session(app: &Router, email: &str) -> String {
    let (_, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth_secret = reg.auth_secret.expose_b64().to_string();
    let reg_value = serde_json::to_value(&reg).unwrap();
    send(
        app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": reg_value })),
    )
    .await;
    let (_, body) = send(
        app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn logout_revokes_token() {
    let app = server::app_in_memory();
    let token = registered_session(&app, "bob@example.com").await;

    // Valid token.
    let (s, _) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);

    // Logout.
    let (s, _) = send(&app, "DELETE", "/sessions", Some(&token), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Token now revoked.
    let (s, _) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    // Zero TTL -> the token is expired by the next request.
    let app = server::app_in_memory_with_ttl(std::time::Duration::ZERO);
    let token = registered_session(&app, "carol@example.com").await;
    let (s, _) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn prelogin_unknown_account_is_404() {
    let app = server::app_in_memory();
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
    let app = server::app_in_memory();
    let (s, _) = send(&app, "GET", "/vault", Some("deadbeef"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_invalid_item_ids_and_oversized_blobs() {
    let app = server::app_in_memory();
    let token = signup_login(&app, "quota@example.com").await;

    let long_id = "a".repeat(257);
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/vault/items/{long_id}"),
        Some(&token),
        Some(json!({
            "blob": { "v": 1, "nonce": B64.encode([0u8; 24]), "ct": "AA==" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let oversized = "A".repeat(600 * 1024);
    let (status, _) = send(
        &app,
        "PUT",
        "/vault/items/oversized",
        Some(&token),
        Some(json!({
            "blob": { "v": 1, "nonce": B64.encode([0u8; 24]), "ct": oversized }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let oversized_manifest = "A".repeat(600 * 1024);
    let (status, _) = send(
        &app,
        "PUT",
        "/vault/manifest",
        Some(&token),
        Some(json!({
            "blob": { "v": 1, "nonce": B64.encode([0u8; 24]), "ct": oversized_manifest }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (_, vault) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(vault["items"], json!({}));
}

#[tokio::test]
async fn health_ok() {
    let app = server::app_in_memory();
    let (s, _) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn data_persists_across_restart() {
    let path = std::env::temp_dir()
        .join(format!("bastion-persist-{}.db", std::process::id()))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);

    let (vault, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth = reg.auth_secret.expose_b64().to_string();
    let reg_value = serde_json::to_value(&reg).unwrap();
    let email = "persist@example.com";

    // ── First "boot": create account + store an encrypted item ──
    {
        let app = server::app_with_db(&path);
        let (s, _) = send(
            &app,
            "POST",
            "/accounts",
            None,
            Some(json!({ "email": email, "registration": reg_value })),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let (_, body) = send(
            &app,
            "POST",
            "/sessions",
            None,
            Some(json!({ "email": email, "auth_secret": auth })),
        )
        .await;
        let token = body["token"].as_str().unwrap().to_string();
        let blob = serde_json::to_value(vault.encrypt_item(b"top-secret", "i1").unwrap()).unwrap();
        let (s, _) = send(
            &app,
            "PUT",
            "/vault/items/i1",
            Some(&token),
            Some(json!({ "blob": blob })),
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
    } // app (and its SQLite connection) dropped → simulates a restart

    // ── Second "boot" from the same database ──
    let app2 = server::app_with_db(&path);
    let (s, body) = send(
        &app2,
        "GET",
        &format!("/accounts/{email}/prelogin"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "account should survive a restart");
    assert_eq!(body["salt"], reg.salt);

    let (_, lb) = send(
        &app2,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth })),
    )
    .await;
    let token = lb["token"].as_str().unwrap().to_string();
    let (_, vb) = send(&app2, "GET", "/vault", Some(&token), None).await;
    let stored: crypto_core::EncryptedBlob =
        serde_json::from_value(vb["items"]["i1"].clone()).unwrap();
    assert_eq!(
        vault.decrypt_item(&stored, "i1").unwrap().as_slice(),
        b"top-secret"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[tokio::test]
async fn corrupt_persisted_vault_state_prevents_restart() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir()
        .join(format!(
            "bastion-corrupt-state-{}-{unique}.db",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();

    let (vault, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth = reg.auth_secret.expose_b64().to_string();
    {
        let app = server::app_with_db(&path);
        let (status, _) = send(
            &app,
            "POST",
            "/accounts",
            None,
            Some(json!({
                "email": "corrupt@example.com",
                "registration": serde_json::to_value(&reg).unwrap()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, login) = send(
            &app,
            "POST",
            "/sessions",
            None,
            Some(json!({
                "email": "corrupt@example.com",
                "auth_secret": auth
            })),
        )
        .await;
        let token = login["token"].as_str().unwrap();
        let blob = vault.encrypt_item(b"secret", "item-1").unwrap();
        let (status, _) = send(
            &app,
            "PUT",
            "/vault/items/item-1",
            Some(token),
            Some(json!({ "blob": blob })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE items SET blob='not-json' WHERE email='corrupt@example.com' AND id='item-1'",
        [],
    )
    .unwrap();
    drop(conn);

    let restart = std::panic::catch_unwind(|| server::app_with_db(&path));
    assert!(
        restart.is_err(),
        "a corrupt persisted item must stop startup instead of disappearing"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_keep_cache_and_sqlite_consistent() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir()
        .join(format!(
            "bastion-write-order-{}-{unique}.db",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();

    let app = server::app_with_db(&path);
    let (vault, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth = reg.auth_secret.expose_b64().to_string();
    let email = "write-order@example.com";
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": serde_json::to_value(&reg).unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, login) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth })),
    )
    .await;
    let token = login["token"].as_str().unwrap().to_string();

    let mut writes = tokio::task::JoinSet::new();
    for value in 0..128 {
        let app = app.clone();
        let token = token.clone();
        let blob = serde_json::to_value(
            vault
                .encrypt_item(value.to_string().as_bytes(), "shared-id")
                .unwrap(),
        )
        .unwrap();
        writes.spawn(async move {
            send(
                &app,
                "PUT",
                "/vault/items/shared-id",
                Some(&token),
                Some(json!({ "blob": blob })),
            )
            .await
            .0
        });
    }
    while let Some(result) = writes.join_next().await {
        assert_eq!(result.unwrap(), StatusCode::NO_CONTENT);
    }

    let (_, live) = send(&app, "GET", "/vault", Some(&token), None).await;
    drop(app);

    let restarted = server::app_with_db(&path);
    let (_, login) = send(
        &restarted,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": reg.auth_secret.expose_b64() })),
    )
    .await;
    let restarted_token = login["token"].as_str().unwrap();
    let (_, persisted) = send(&restarted, "GET", "/vault", Some(restarted_token), None).await;
    assert_eq!(
        live["items"]["shared-id"], persisted["items"]["shared-id"],
        "live reads and restart reads must select the same concurrent winner"
    );

    drop(restarted);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

/// Sign up + log in an account; returns its bearer token. Uses the email as the
/// master password for test determinism/uniqueness.
async fn signup_login(app: &Router, email: &str) -> String {
    let (_v, reg, _sk) = Vault::register_with(email.as_bytes(), fast_kdf()).unwrap();
    let auth = reg.auth_secret.expose_b64().to_string();
    let regv = serde_json::to_value(&reg).unwrap();
    let (s, _) = send(
        app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": regv })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, b) = send(
        app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    b["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn bastion_send_directory_and_inbox_flow() {
    let app = server::app_in_memory();
    let alice = signup_login(&app, "alice@example.com").await;
    let bob = signup_login(&app, "bob@example.com").await;

    // Send endpoints require auth.
    let (s, _) = send(&app, "GET", "/send/inbox", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Bob publishes his (opaque) public identity → stable Bastion ID.
    let bob_pub = json!({ "enc_pub": "b-enc", "sig_pub": "b-sig", "key_version": 1 });
    let (s, b) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&bob),
        Some(bob_pub.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bob_id = b["bastion_id"].as_str().unwrap().to_string();
    assert!(!bob_id.is_empty());

    // whoami echoes it; re-publishing keeps the same id.
    let (_s, w) = send(&app, "GET", "/send/whoami", Some(&bob), None).await;
    assert_eq!(w["bastion_id"], bob_id);
    let (_s, b2) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&bob),
        Some(json!({ "enc_pub": "b-enc2" })),
    )
    .await;
    assert_eq!(
        b2["bastion_id"], bob_id,
        "rotation keeps the bastion_id stable"
    );

    // Alice publishes too (so she has an inbox of her own).
    let (_s, _) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&alice),
        Some(json!({ "enc_pub": "a-enc" })),
    )
    .await;

    // Fetching an inbox with no published identity → 404 (Carol never published).
    let carol = signup_login(&app, "carol@example.com").await;
    let (s, _) = send(&app, "GET", "/send/inbox", Some(&carol), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Alice resolves Bob's directory entry; unknown id → 404.
    let (s, dir) = send(
        &app,
        "GET",
        &format!("/send/directory/{bob_id}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(dir["enc_pub"], "b-enc2");
    let (s, _) = send(&app, "GET", "/send/directory/NOPE", Some(&alice), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Alice sends an opaque blob to Bob.
    let post = |mid: &str, exp: Option<i64>| json!({ "recipient_id": bob_id, "message_id": mid, "blob": { "v": 1, "ct": "opaque" }, "expires_at": exp });
    let (s, _) = send(&app, "POST", "/send", Some(&alice), Some(post("m1", None))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Replay (same message_id) → 409.
    let (s, _) = send(&app, "POST", "/send", Some(&alice), Some(post("m1", None))).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Unknown recipient → 404.
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(json!({ "recipient_id": "NOPE", "message_id": "m2", "blob": {} })),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // An already-expired message is delivered but filtered out of the inbox.
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post("m-exp", Some(1))),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Bob's inbox has m1 only; Alice's inbox is empty.
    let (s, inbox) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<&str> = inbox
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m1"]);
    let (_s, ainbox) = send(&app, "GET", "/send/inbox", Some(&alice), None).await;
    assert_eq!(ainbox.as_array().unwrap().len(), 0);

    // Bob reads-once: delete m1.
    let (s, _) = send(&app, "DELETE", "/send/inbox/m1", Some(&bob), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_s, inbox) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(inbox.as_array().unwrap().len(), 0);

    // Oversized blob → 413.
    let big = "X".repeat(300 * 1024);
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(json!({ "recipient_id": bob_id, "message_id": "big", "blob": { "ct": big } })),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

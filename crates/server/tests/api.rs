//! Integration tests for the server API (via `tower::oneshot`, no network).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use tower::ServiceExt;

use crypto_core::kdf::KdfParams;
use crypto_core::{send_seal, IdentityKeys, Manifest, SendBlob, Vault};

fn fast_kdf() -> KdfParams {
    KdfParams {
        mem_kib: KdfParams::MIN_MEM_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: KdfParams::MIN_PARALLELISM,
    }
}

struct TestDbPath {
    path: String,
    directory: PathBuf,
}

impl Deref for TestDbPath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for TestDbPath {
    fn as_ref(&self) -> &Path {
        Path::new(&self.path)
    }
}

impl fmt::Display for TestDbPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.fmt(formatter)
    }
}

impl Drop for TestDbPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        for suffix in ["-wal", "-shm", "-journal", "-server.lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn test_db_path(label: &str) -> TestDbPath {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("bastion-{label}-{}-{unique}", std::process::id()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).unwrap();
    TestDbPath {
        path: directory.join("bastion.db").to_string_lossy().into_owned(),
        directory,
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
    assert_eq!(body["revision"], 1);
    let stored: crypto_core::EncryptedBlob =
        serde_json::from_value(body["items"]["github.com"].clone()).unwrap();
    let plain = vault.decrypt_item(&stored, "github.com").unwrap();
    assert_eq!(plain.as_slice(), b"hunter2");
    let (s, revision) = send(&app, "GET", "/v1/vault/revision", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(revision, json!({ "revision": 1 }));

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
    assert_eq!(body["revision"], 2);
}

#[tokio::test]
async fn mailbox_proof_precedes_account_creation_and_is_consumed_atomically() {
    let path = test_db_path("mailbox-proof");
    let app = server::app_with_db_and_mailbox_verification(&path, "https://vault.example.com");
    let email = "verified@example.com";
    let (_vault, registration, _secret_key) =
        Vault::register_with(b"verified-password", fast_kdf()).unwrap();
    let auth_secret = registration.auth_secret.expose_b64().to_string();
    let registration = serde_json::to_value(registration).unwrap();

    let (status, config) = send(&app, "GET", "/v1/config", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(config["email_verification_required"], true);

    let (status, _) = send(
        &app,
        "POST",
        "/v1/registration-challenges",
        None,
        Some(json!({ "email": email })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let account_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        account_count, 0,
        "challenge creation squatted the account id"
    );
    let body: String = conn
        .query_row("SELECT text_body FROM mail_outbox", [], |row| row.get(0))
        .unwrap();
    let token = body
        .split("#token=")
        .nth(1)
        .and_then(|tail| tail.lines().next())
        .unwrap()
        .to_string();
    drop(conn);
    let snapshot = server::operational_snapshot(path.as_ref()).unwrap();
    assert_eq!(snapshot.schema_version, 4);
    assert_eq!(snapshot.accounts, 0);
    assert_eq!(snapshot.registration_challenges_active, 1);
    assert_eq!(snapshot.registration_challenges_verified, 0);
    assert_eq!(snapshot.registration_challenges_expired, 0);
    assert_eq!(snapshot.mail_pending, 1);
    assert_eq!(snapshot.mail_in_flight, 0);
    assert_eq!(snapshot.mail_dead, 0);
    assert!(snapshot.database_bytes > 0);
    assert!(snapshot.oldest_active_mail_age_seconds.is_some());
    let snapshot_json = serde_json::to_value(&snapshot).unwrap();
    let snapshot_fields = snapshot_json.as_object().unwrap();
    assert_eq!(snapshot_fields.len(), 11);
    for field in [
        "observed_at",
        "schema_version",
        "database_bytes",
        "accounts",
        "registration_challenges_active",
        "registration_challenges_verified",
        "registration_challenges_expired",
        "mail_pending",
        "mail_in_flight",
        "mail_dead",
        "oldest_active_mail_age_seconds",
    ] {
        assert!(snapshot_fields.contains_key(field), "missing {field}");
    }
    assert!(!snapshot_json.to_string().contains(email));

    let (status, _) = send(
        &app,
        "POST",
        "/v1/accounts",
        None,
        Some(json!({ "email": email, "registration": registration.clone() })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, verified) = send(
        &app,
        "POST",
        "/v1/registration-challenges/verify",
        None,
        Some(json!({ "token": token.clone() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verified["email"], email);

    let (status, _) = send(
        &app,
        "POST",
        "/v1/accounts",
        None,
        Some(json!({
            "email": email,
            "registration": registration,
            "mailbox_proof": token
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = send(
        &app,
        "POST",
        "/v1/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let conn = rusqlite::Connection::open(&path).unwrap();
    for table in ["registration_challenges", "mail_outbox"] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} survived proof consumption");
    }
    drop(conn);
    let snapshot = server::operational_snapshot(path.as_ref()).unwrap();
    assert_eq!(snapshot.accounts, 1);
    assert_eq!(snapshot.registration_challenges_active, 0);
    assert_eq!(snapshot.mail_pending, 0);
    assert_eq!(snapshot.oldest_active_mail_age_seconds, None);
}

#[tokio::test]
async fn atomic_vault_transactions_apply_once_and_reject_stale_writers() {
    let app = server::app_in_memory();
    let (vault, token) = registered_vault_session(&app, "atomic@example.com").await;

    let first = vault.encrypt_item(b"first", "item-1").unwrap();
    let mut manifest = Manifest::new();
    manifest.set("item-1", &first).unwrap();
    let first_manifest = vault.seal_manifest(&manifest).unwrap();
    let (status, response) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 0,
            "operations": [{ "op": "put", "id": "item-1", "blob": first }],
            "manifest": first_manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["revision"], 1);

    let stale = vault.encrypt_item(b"stale", "item-1").unwrap();
    manifest.set("item-1", &stale).unwrap();
    let stale_manifest = vault.seal_manifest(&manifest).unwrap();
    let (status, _) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 0,
            "operations": [{ "op": "put", "id": "item-1", "blob": stale }],
            "manifest": stale_manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (_, stored) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(stored["revision"], 1);
    let stored_blob = serde_json::from_value(stored["items"]["item-1"].clone()).unwrap();
    assert_eq!(
        vault
            .decrypt_item(&stored_blob, "item-1")
            .unwrap()
            .as_slice(),
        b"first"
    );

    let mut committed_manifest = Manifest::new();
    committed_manifest.set("item-1", &stored_blob).unwrap();
    committed_manifest.remove("item-1").unwrap();
    let empty_manifest = vault.seal_manifest(&committed_manifest).unwrap();
    let (status, response) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 1,
            "operations": [{ "op": "delete", "id": "item-1" }],
            "manifest": empty_manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["revision"], 2);
    let (_, stored) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(stored["items"], json!({}));
    assert_eq!(stored["revision"], 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_vault_transactions_have_one_cas_winner() {
    let app = server::app_in_memory();
    let (vault, token) = registered_vault_session(&app, "cas@example.com").await;

    let transaction = |value: &'static [u8]| {
        let item = vault.encrypt_item(value, "shared").unwrap();
        let mut manifest = Manifest::new();
        manifest.set("shared", &item).unwrap();
        let sealed = vault.seal_manifest(&manifest).unwrap();
        json!({
            "expected_revision": 0,
            "operations": [{ "op": "put", "id": "shared", "blob": item }],
            "manifest": sealed
        })
    };
    let first = transaction(b"first");
    let second = transaction(b"second");
    let (first_result, second_result) = tokio::join!(
        send(&app, "PUT", "/vault/transaction", Some(&token), Some(first)),
        send(
            &app,
            "PUT",
            "/vault/transaction",
            Some(&token),
            Some(second)
        ),
    );
    let statuses = [first_result.0, second_result.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
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
    let (_, stored) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(stored["revision"], 1);
}

#[tokio::test]
async fn transaction_validation_is_atomic_and_supports_large_manifests() {
    let app = server::app_in_memory();
    let (vault, token) = registered_vault_session(&app, "bounds@example.com").await;
    let item = vault.encrypt_item(b"value", "duplicate").unwrap();
    let manifest = vault.seal_manifest(&Manifest::new()).unwrap();

    let (status, _) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 0,
            "operations": [
                { "op": "put", "id": "duplicate", "blob": item },
                { "op": "delete", "id": "duplicate" }
            ],
            "manifest": manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, unchanged) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(unchanged["revision"], 0);
    assert_eq!(unchanged["items"], json!({}));
    assert!(unchanged["manifest"].is_null());

    let large_manifest = json!({
        "v": 1,
        "nonce": B64.encode([0u8; 24]),
        "ct": "A".repeat(1_100_000)
    });
    let (status, response) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 0,
            "operations": [],
            "manifest": large_manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["revision"], 1);
}

#[tokio::test]
async fn failed_manifest_persistence_rolls_back_items_and_revision() {
    let path = test_db_path("transaction-rollback");
    let app = server::app_with_db(&path);
    let (vault, token) = registered_vault_session(&app, "rollback@example.com").await;
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_manifest BEFORE INSERT ON manifests
         BEGIN SELECT RAISE(ABORT, 'forced manifest failure'); END;",
    )
    .unwrap();
    drop(conn);

    let item = vault.encrypt_item(b"must-not-commit", "item").unwrap();
    let mut manifest = Manifest::new();
    manifest.set("item", &item).unwrap();
    let sealed = vault.seal_manifest(&manifest).unwrap();
    let (status, _) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 0,
            "operations": [{ "op": "put", "id": "item", "blob": item }],
            "manifest": sealed
        })),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (_, unchanged) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(unchanged["revision"], 0);
    assert_eq!(unchanged["items"], json!({}));
    assert!(unchanged["manifest"].is_null());

    drop(app);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let persisted_revision: i64 = conn
        .query_row(
            "SELECT vault_revision FROM accounts WHERE email='rollback@example.com'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let persisted_items: i64 = conn
        .query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(persisted_revision, 0);
    assert_eq!(persisted_items, 0);
    drop(conn);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
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
    assert_eq!(status, StatusCode::OK); // unknown account answers with a decoy
}

#[tokio::test]
async fn rate_limits_account_creation_globally_and_per_account_before_hashing() {
    let app = server::app_in_memory_with_auth_rate_limits(server::AuthRateLimits {
        max_entries: 16,
        window: std::time::Duration::from_secs(60),
        account_creations_global: 2,
        account_creations_per_account: 1,
        login_attempts_global: 10,
        login_attempts_per_account: 10,
        prelogins_global: 100,
        prelogins_per_account: 100,
    });
    let (_, first, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let first = serde_json::to_value(first).unwrap();

    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "limited-signup@example.com",
            "registration": first
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The second request consumes the remaining global allowance, then the
    // account-specific limiter rejects it before duplicate lookup or Argon2.
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "limited-signup@example.com",
            "registration": first
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let (_, second, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "globally-limited-signup@example.com",
            "registration": serde_json::to_value(second).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let (status, _) = send(
        &app,
        "GET",
        "/accounts/globally-limited-signup@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK); // unknown account answers with a decoy
}

#[tokio::test]
async fn rate_limits_login_globally_and_per_account_before_verification() {
    let app = server::app_in_memory_with_auth_rate_limits(server::AuthRateLimits {
        max_entries: 16,
        window: std::time::Duration::from_secs(60),
        account_creations_global: 10,
        account_creations_per_account: 2,
        login_attempts_global: 3,
        login_attempts_per_account: 1,
        prelogins_global: 100,
        prelogins_per_account: 100,
    });
    for email in ["login-alice@example.com", "login-bob@example.com"] {
        let (_, registration, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
        let (status, _) = send(
            &app,
            "POST",
            "/accounts",
            None,
            Some(json!({
                "email": email,
                "registration": serde_json::to_value(registration).unwrap()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let wrong_secret = B64.encode([0u8; 32]);

    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "login-alice@example.com",
            "auth_secret": wrong_secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "login-alice@example.com",
            "auth_secret": wrong_secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "login-bob@example.com",
            "auth_secret": wrong_secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "another-account@example.com",
            "auth_secret": wrong_secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn authentication_rate_state_is_strictly_bounded() {
    let app = server::app_in_memory_with_auth_rate_limits(server::AuthRateLimits {
        max_entries: 2,
        window: std::time::Duration::from_secs(60),
        account_creations_global: 10,
        account_creations_per_account: 10,
        login_attempts_global: 10,
        login_attempts_per_account: 10,
        prelogins_global: 100,
        prelogins_per_account: 100,
    });
    let (_, first, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "rate-capacity-first@example.com",
            "registration": serde_json::to_value(first).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (_, second, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "rate-capacity-second@example.com",
            "registration": serde_json::to_value(second).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Prelogin now participates in the bounded auth-rate map: at capacity a
    // new live key is refused rather than growing the map without bound.
    let (status, _) = send(
        &app,
        "GET",
        "/accounts/rate-capacity-second@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn rate_limiter_state_is_strictly_bounded_and_reclaims_expired_windows() {
    let unknown_id = data_encoding::BASE32_NOPAD.encode(&[0u8; 16]);
    let path = format!("/send/directory/{unknown_id}");
    let app = server::app_in_memory_with_rate_limits(2, std::time::Duration::from_secs(60));
    let alice = signup_login(&app, "rate-alice@example.com").await;
    let bob = signup_login(&app, "rate-bob@example.com").await;
    let carol = signup_login(&app, "rate-carol@example.com").await;

    let (status, _) = send(&app, "GET", &path, Some(&alice), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, "GET", &path, Some(&bob), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Existing keys remain serviceable at capacity, but a third live key is
    // rejected before it can grow the map past its configured bound.
    let (status, _) = send(&app, "GET", &path, Some(&alice), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, "GET", &path, Some(&carol), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // A zero-length deterministic test window makes the previous entry
    // immediately reclaimable for a different subject.
    let reclaiming = server::app_in_memory_with_rate_limits(1, std::time::Duration::ZERO);
    let first = signup_login(&reclaiming, "rate-first@example.com").await;
    let second = signup_login(&reclaiming, "rate-second@example.com").await;
    let (status, _) = send(&reclaiming, "GET", &path, Some(&first), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&reclaiming, "GET", &path, Some(&second), None).await;
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
async fn registered_vault_session(app: &Router, email: &str) -> (Vault, String) {
    let (vault, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth_secret = reg.auth_secret.expose_b64().to_string();
    let reg_value = serde_json::to_value(&reg).unwrap();
    let (status, _) = send(
        app,
        "POST",
        "/accounts",
        None,
        Some(json!({ "email": email, "registration": reg_value })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(
        app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (vault, body["token"].as_str().unwrap().to_string())
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
async fn prelogin_unknown_account_returns_stable_decoy() {
    let app = server::app_in_memory();
    let (s1, first) = send(
        &app,
        "GET",
        "/accounts/ghost@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, second) = send(
        &app,
        "GET",
        "/accounts/ghost@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    // Deterministic: probing twice yields byte-identical decoys.
    assert_eq!(first, second);
    // Distinct emails yield distinct decoys (no shared tell-tale value).
    let (s3, other) = send(
        &app,
        "GET",
        "/accounts/ghost2@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(s3, StatusCode::OK);
    assert_ne!(first, other);
    assert_ne!(first["salt"], other["salt"]);
    // Shaped like a real registration: registration-default KDF params and a
    // v1 wrapped key with 24-byte nonce / 48-byte ciphertext.
    assert_eq!(first["kdf"]["mem_kib"], 64 * 1024);
    assert_eq!(first["kdf"]["iterations"], 3);
    assert_eq!(first["wrapped_vault_key"]["v"], 1);
    let b64_len = |value: &serde_json::Value| value.as_str().unwrap().len();
    assert_eq!(b64_len(&first["salt"]), 24); // 16 bytes
    assert_eq!(b64_len(&first["wrapped_vault_key"]["nonce"]), 32); // 24 bytes
    assert_eq!(b64_len(&first["wrapped_vault_key"]["ct"]), 64); // 48 bytes
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

    let oversized_manifest = "A".repeat(2 * 1024 * 1024);
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
    for route in ["/health", "/livez", "/readyz"] {
        let (status, body) = send(&app, "GET", route, None, None).await;
        assert_eq!(status, StatusCode::OK, "{route} was not healthy");
        assert_eq!(body, Value::Null); // "ok" is plain text, not JSON
    }
}

#[tokio::test]
async fn versioned_api_is_canonical_and_legacy_routes_are_marked_deprecated() {
    let app = server::app_in_memory();
    let versioned = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(versioned.status(), StatusCode::OK);
    assert!(versioned.headers().get("deprecation").is_none());

    let legacy = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(legacy.status(), StatusCode::OK);
    assert_eq!(legacy.headers()["deprecation"], "true");
    assert_eq!(
        legacy.headers()[header::LINK],
        "</v1>; rel=\"successor-version\""
    );
}

#[tokio::test]
async fn account_deletion_requires_fresh_proof_and_removes_owned_state() {
    let path = test_db_path("account-deletion");
    let app = server::app_with_db(&path);
    let email = "delete-me@example.com";
    let (vault, registration, _secret_key) =
        Vault::register_with(b"delete-password", fast_kdf()).unwrap();
    let auth_secret = registration.auth_secret.expose_b64().to_string();
    let (status, _) = send(
        &app,
        "POST",
        "/v1/accounts",
        None,
        Some(json!({
            "email": email,
            "registration": serde_json::to_value(&registration).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, login) = send(
        &app,
        "POST",
        "/v1/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = login["token"].as_str().unwrap().to_string();
    let (_, second_login) = send(
        &app,
        "POST",
        "/v1/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    let second_token = second_login["token"].as_str().unwrap().to_string();

    let item = vault.encrypt_item(b"owned", "owned-item").unwrap();
    let mut manifest = Manifest::new();
    manifest.set("owned-item", &item).unwrap();
    let sealed_manifest = vault.seal_manifest(&manifest).unwrap();
    let (status, _) = send(
        &app,
        "PUT",
        "/v1/vault/transaction",
        Some(&token),
        Some(json!({
            "expected_revision": 0,
            "operations": [{ "op": "put", "id": "owned-item", "blob": item }],
            "manifest": sealed_manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let identity = IdentityKeys::generate(1);
    let (status, published) = send(
        &app,
        "PUT",
        "/v1/send/identity",
        Some(&token),
        Some(serde_json::to_value(identity.public()).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bastion_id = published["bastion_id"].as_str().unwrap().to_string();
    let sender = signup_login(&app, "deletion-sender@example.com").await;
    let envelope = send_seal(b"pending", &bastion_id, &identity.public(), None, None).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/v1/send",
        Some(&sender),
        Some(json!({
            "recipient_id": bastion_id,
            "message_id": envelope.message_id,
            "blob": envelope,
            "expires_at": null
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &app,
        "DELETE",
        "/v1/accounts",
        Some(&token),
        Some(json!({ "auth_secret": B64.encode([0u8; 32]) })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(&app, "GET", "/v1/vault", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(
        &app,
        "DELETE",
        "/v1/accounts",
        Some(&token),
        Some(json!({ "auth_secret": auth_secret })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "GET", "/v1/vault", Some(&second_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        "GET",
        &format!("/v1/send/directory/{bastion_id}"),
        Some(&sender),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    drop(app);
    let conn = rusqlite::Connection::open(&path).unwrap();
    for (table, column, value) in [
        ("accounts", "email", email),
        ("items", "email", email),
        ("manifests", "email", email),
        ("send_directory", "email", email),
        ("send_inbox", "recipient_id", bastion_id.as_str()),
    ] {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                [value],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "owned rows remained in {table}");
    }
}

#[tokio::test]
async fn health_reports_unavailable_when_the_schema_is_gone() {
    let path = test_db_path("health");
    let app = server::app_with_db(&path.to_string());
    let (s, _) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::OK);

    // Simulate a wedged database: another connection drops the accounts table.
    // The server's cached connection then observes the missing schema and the
    // health check must fail closed instead of reporting healthy.
    let breaker = rusqlite::Connection::open(&path).unwrap();
    breaker.execute_batch("DROP TABLE accounts;").unwrap();
    drop(breaker);

    let (s, _) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _) = send(&app, "GET", "/readyz", None, None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _) = send(&app, "GET", "/livez", None, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&app, "POST", "/accounts", None, Some(json!({}))).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[cfg(unix)]
#[test]
fn creates_sqlite_artifacts_and_instance_lock_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let path = test_db_path("owner-only");
    let app = server::app_with_db(&path);
    for artifact in [
        path.to_string(),
        format!("{path}-wal"),
        format!("{path}-shm"),
        format!("{path}-server.lock"),
    ] {
        let metadata = std::fs::symlink_metadata(&artifact).unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    drop(app);
}

#[cfg(unix)]
#[test]
fn tightens_existing_database_permissions_before_opening() {
    use std::os::unix::fs::PermissionsExt;

    let path = test_db_path("tighten-permissions");
    std::fs::write(&*path, []).unwrap();
    std::fs::set_permissions(&*path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(server::app_with_db(&path));
    assert_eq!(
        std::fs::metadata(&*path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn rejects_symbolic_link_database_and_sidecar_paths() {
    use std::os::unix::fs::symlink;

    let linked_database = test_db_path("linked-database");
    let database_target = linked_database.directory.join("target.db");
    std::fs::write(&database_target, []).unwrap();
    symlink(&database_target, &*linked_database).unwrap();
    assert!(std::panic::catch_unwind(|| server::app_with_db(&linked_database)).is_err());
    std::fs::remove_file(&database_target).unwrap();

    let linked_sidecar = test_db_path("linked-sidecar");
    std::fs::write(&*linked_sidecar, []).unwrap();
    let sidecar_target = linked_sidecar.directory.join("target.wal");
    std::fs::write(&sidecar_target, []).unwrap();
    symlink(&sidecar_target, format!("{linked_sidecar}-wal")).unwrap();
    assert!(std::panic::catch_unwind(|| server::app_with_db(&linked_sidecar)).is_err());
    std::fs::remove_file(&sidecar_target).unwrap();

    let linked_lock = test_db_path("linked-lock");
    std::fs::write(&*linked_lock, []).unwrap();
    let lock_target = linked_lock.directory.join("target.lock");
    std::fs::write(&lock_target, []).unwrap();
    symlink(&lock_target, format!("{linked_lock}-server.lock")).unwrap();
    assert!(std::panic::catch_unwind(|| server::app_with_db(&linked_lock)).is_err());
    std::fs::remove_file(&lock_target).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_hard_linked_database_and_lock_paths() {
    let path = test_db_path("hard-linked-database");
    std::fs::write(&*path, []).unwrap();
    let alias = path.directory.join("database-alias.db");
    std::fs::hard_link(&*path, &alias).unwrap();
    assert!(std::panic::catch_unwind(|| server::app_with_db(&path)).is_err());
    std::fs::remove_file(alias).unwrap();

    let locked_path = test_db_path("hard-linked-lock");
    std::fs::write(&*locked_path, []).unwrap();
    let lock_path = format!("{locked_path}-server.lock");
    std::fs::write(&lock_path, []).unwrap();
    let lock_alias = locked_path.directory.join("server-lock-alias");
    std::fs::hard_link(&lock_path, &lock_alias).unwrap();
    assert!(std::panic::catch_unwind(|| server::app_with_db(&locked_path)).is_err());
    std::fs::remove_file(lock_alias).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_database_parent_writable_by_group_or_others() {
    use std::os::unix::fs::PermissionsExt;

    let path = test_db_path("unsafe-parent");
    std::fs::set_permissions(&path.directory, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(std::panic::catch_unwind(|| server::app_with_db(&path)).is_err());
}

#[test]
fn refuses_a_second_server_for_the_same_database() {
    let path = test_db_path("single-server");
    let first = server::app_with_db(&path);
    let second = std::panic::catch_unwind(|| server::app_with_db(&path));
    assert!(
        second.is_err(),
        "a second process-local cache must not share one SQLite database"
    );

    drop(first);
    drop(server::app_with_db(&path));
}

#[tokio::test]
async fn data_persists_across_restart() {
    let path = test_db_path("persist");
    let _ = std::fs::remove_file(&path);

    let (vault, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let auth = reg.auth_secret.expose_b64().to_string();
    let reg_value = serde_json::to_value(&reg).unwrap();
    let email = "persist@example.com";

    // ── First "boot": create account + atomically store item and manifest ──
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
        let typed_blob = serde_json::from_value(blob.clone()).unwrap();
        let mut manifest = Manifest::new();
        manifest.set("i1", &typed_blob).unwrap();
        let sealed_manifest = vault.seal_manifest(&manifest).unwrap();
        let (s, response) = send(
            &app,
            "PUT",
            "/vault/transaction",
            Some(&token),
            Some(json!({
                "expected_revision": 0,
                "operations": [{ "op": "put", "id": "i1", "blob": blob }],
                "manifest": sealed_manifest
            })),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(response["revision"], 1);
    } // app (and its SQLite connection) dropped → simulates a restart

    // WAL is a persistent database property. Verify the file-backed server
    // actually selected it instead of silently accepting another journal mode.
    let persisted_journal_mode: String = rusqlite::Connection::open(&*path)
        .unwrap()
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(persisted_journal_mode.to_ascii_lowercase(), "wal");

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
    assert_eq!(vb["revision"], 1);
    assert!(!vb["manifest"].is_null());
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
async fn live_backup_restores_vault_and_send_state() {
    let source = test_db_path("live-backup");
    let backup_path = source.directory.join("snapshot.db");
    let app = server::app_with_db(&source);
    let email = "backup@example.com";
    let (vault, registration, _secret_key) =
        Vault::register_with(b"backup-master", fast_kdf()).unwrap();
    let auth_secret = registration.auth_secret.expose_b64().to_string();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": email,
            "registration": serde_json::to_value(&registration).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, login) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({ "email": email, "auth_secret": auth_secret })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = login["token"].as_str().unwrap();

    let item = vault
        .encrypt_item(b"restored-secret", "backup-item")
        .unwrap();
    let mut manifest = Manifest::new();
    manifest.set("backup-item", &item).unwrap();
    let sealed_manifest = vault.seal_manifest(&manifest).unwrap();
    let (status, revision) = send(
        &app,
        "PUT",
        "/vault/transaction",
        Some(token),
        Some(json!({
            "expected_revision": 0,
            "operations": [{ "op": "put", "id": "backup-item", "blob": item }],
            "manifest": sealed_manifest
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revision["revision"], 1);

    let identity = IdentityKeys::generate(1);
    let public = identity.public();
    let (status, published) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(token),
        Some(serde_json::to_value(&public).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bastion_id = published["bastion_id"].as_str().unwrap();
    let send_blob = send_seal(b"restored-send", bastion_id, &public, None, None).unwrap();
    let message_id = send_blob.message_id.clone();
    let (status, _) = send(
        &app,
        "POST",
        "/send",
        Some(token),
        Some(json!({
            "recipient_id": send_blob.recipient_id,
            "message_id": send_blob.message_id,
            "blob": send_blob,
            "expires_at": null
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let backup_source = PathBuf::from(source.as_ref());
    let backup_destination = backup_path.clone();
    tokio::task::spawn_blocking(move || {
        server::backup_database(&backup_source, &backup_destination)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(backup_path.is_file());
    assert!(server::backup_database(source.as_ref(), &backup_path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    drop(app);
    let restored_path = backup_path.to_string_lossy().into_owned();
    let restored = server::app_with_db(&restored_path);
    let (status, login) = send(
        &restored,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": email,
            "auth_secret": registration.auth_secret.expose_b64()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let restored_token = login["token"].as_str().unwrap();
    let (status, snapshot) = send(&restored, "GET", "/vault", Some(restored_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot["revision"], 1);
    assert!(!snapshot["manifest"].is_null());
    let restored_item: crypto_core::EncryptedBlob =
        serde_json::from_value(snapshot["items"]["backup-item"].clone()).unwrap();
    assert_eq!(
        vault
            .decrypt_item(&restored_item, "backup-item")
            .unwrap()
            .as_slice(),
        b"restored-secret"
    );
    let (status, inbox) = send(&restored, "GET", "/send/inbox", Some(restored_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["message_id"], message_id);

    drop(restored);
    let _ = std::fs::remove_file(&backup_path);
    for suffix in ["-wal", "-shm", "-journal", "-server.lock"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", backup_path.display()));
    }
}

#[test]
fn migrates_legacy_accounts_with_zero_vault_revision() {
    let path = test_db_path("revision-migration");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE accounts(
           email TEXT PRIMARY KEY, salt TEXT NOT NULL, kdf TEXT NOT NULL,
           wrapped_vault_key TEXT NOT NULL, auth_hash TEXT NOT NULL);",
    )
    .unwrap();
    drop(conn);

    drop(server::app_with_db(&path));

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    let columns = conn
        .prepare("PRAGMA table_info(accounts)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(columns.iter().any(|column| column == "vault_revision"));
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(user_version, 4);
    assert!(conn
        .execute(
            "INSERT INTO items(email,id,blob) VALUES('missing@example.com','orphan','{}')",
            [],
        )
        .is_err());
    conn.execute(
        "INSERT INTO accounts(
           email,salt,kdf,wrapped_vault_key,auth_hash,vault_revision
         ) VALUES('cascade@example.com','salt','{}','{}','hash',0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO items(email,id,blob) VALUES('cascade@example.com','item','{}')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO send_directory(email,bastion_id,public,created_at)
         VALUES('cascade@example.com','recipient','{}',1)",
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
        "INSERT INTO mail_outbox(
           id,account_email,challenge_email,recipient,subject,text_body,state,attempts,available_at,created_at
         ) VALUES(
           '00112233445566778899aabbccddeeff','cascade@example.com',NULL,
           'cascade@example.com','Subject','Body','pending',0,1,1
         )",
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM accounts WHERE email='cascade@example.com'", [])
        .unwrap();
    for table in ["items", "send_directory", "send_inbox", "mail_outbox"] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} did not cascade on account deletion");
    }
    drop(conn);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[test]
fn refuses_a_database_from_a_newer_schema_version() {
    let path = test_db_path("newer-schema");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA user_version=999").unwrap();
    drop(conn);

    let restart = std::panic::catch_unwind(|| server::app_with_db(&path));
    assert!(restart.is_err(), "newer database schema was accepted");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
    let _ = std::fs::remove_file(format!("{path}-server.lock"));
}

#[tokio::test]
async fn corrupt_persisted_account_credentials_prevent_restart() {
    let path = test_db_path("corrupt-credentials");
    let email = "persisted-credentials@example.com";
    let app = server::app_with_db(&path);
    let (_vault, _token) = registered_vault_session(&app, email).await;
    drop(app);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let (salt, kdf, wrapped, auth_hash): (String, String, String, String) = conn
        .query_row(
            "SELECT salt,kdf,wrapped_vault_key,auth_hash FROM accounts WHERE email=?1",
            [email],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    drop(conn);

    let excessive_auth_cost = auth_hash.replacen("m=19456", "m=4294967295", 1);
    assert_ne!(excessive_auth_cost, auth_hash);
    let wrong_auth_algorithm = auth_hash.replacen("$argon2id$", "$argon2i$", 1);
    assert_ne!(wrong_auth_algorithm, auth_hash);
    let cases = [
        ("salt", "AAAA".to_string(), salt.clone()),
        (
            "kdf",
            json!({ "mem_kib": 0, "iterations": 0, "parallelism": 0 }).to_string(),
            kdf.clone(),
        ),
        (
            "wrapped_vault_key",
            json!({ "v": 1, "nonce": "AA==", "ct": "AA==" }).to_string(),
            wrapped.clone(),
        ),
        ("auth_hash", "not-a-phc".to_string(), auth_hash.clone()),
        ("auth_hash", excessive_auth_cost, auth_hash.clone()),
        ("auth_hash", wrong_auth_algorithm, auth_hash.clone()),
    ];

    for (column, invalid, original) in cases {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            &format!("UPDATE accounts SET {column}=?1 WHERE email=?2"),
            rusqlite::params![invalid, email],
        )
        .unwrap();
        drop(conn);

        let restart = std::panic::catch_unwind(|| server::app_with_db(&path));
        assert!(
            restart.is_err(),
            "corrupted persisted {column} was accepted"
        );

        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            &format!("UPDATE accounts SET {column}=?1 WHERE email=?2"),
            rusqlite::params![original, email],
        )
        .unwrap();
    }

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE accounts SET email=' malformed@example.com' WHERE email=?1",
        [email],
    )
    .unwrap();
    drop(conn);
    let restart = std::panic::catch_unwind(|| server::app_with_db(&path));
    assert!(restart.is_err(), "corrupted persisted email was accepted");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[tokio::test]
async fn corrupt_persisted_vault_state_prevents_restart() {
    let path = test_db_path("corrupt-state");

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
    let path = test_db_path("write-order");

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

    // Bob publishes a validated public identity → stable Bastion ID.
    let bob_v1 = IdentityKeys::generate(1);
    let bob_v1_public = bob_v1.public();
    let bob_pub = serde_json::to_value(&bob_v1_public).unwrap();
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

    // whoami echoes it; an identical retry keeps the same id.
    let (_s, w) = send(&app, "GET", "/send/whoami", Some(&bob), None).await;
    assert_eq!(w["bastion_id"], bob_id);
    let (s, retry) = send(&app, "PUT", "/send/identity", Some(&bob), Some(bob_pub)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(retry["bastion_id"], bob_id);

    // A bearer token is not rotation authority. Changed keys are rejected and
    // the originally published directory entry remains authoritative.
    let bob_v2 = IdentityKeys::generate(2);
    let bob_v2_public = bob_v2.public();
    let (s, _) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&bob),
        Some(serde_json::to_value(&bob_v2_public).unwrap()),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&bob),
        Some(json!({ "enc_pub": vec![0; 32], "sig_pub": vec![0; 32], "key_version": 3 })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "weak public keys are rejected");
    let (s, whoami) = send(&app, "GET", "/send/whoami", Some(&bob), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        whoami["public"],
        serde_json::to_value(&bob_v1_public).unwrap()
    );

    // Alice publishes too (so she has an inbox of her own).
    let alice_identity = IdentityKeys::generate(1);
    let (s, _) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&alice),
        Some(serde_json::to_value(alice_identity.public()).unwrap()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

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
    assert_eq!(dir, serde_json::to_value(&bob_v1_public).unwrap());
    let unknown_id = data_encoding::BASE32_NOPAD.encode(&[0u8; 16]);
    let (s, _) = send(
        &app,
        "GET",
        &format!("/send/directory/{unknown_id}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = send(&app, "GET", "/send/directory/NOPE", Some(&alice), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Alice sends a structurally valid envelope to Bob's current key.
    let blob = send_seal(
        b"hello bob",
        &bob_id,
        &bob_v1_public,
        None,
        Some((&alice_identity, "ALICE")),
    )
    .unwrap();
    let post = |blob: &SendBlob, exp: Option<i64>| {
        json!({
            "recipient_id": blob.recipient_id,
            "message_id": blob.message_id,
            "blob": blob,
            "expires_at": exp,
        })
    };

    // Routing metadata and the current directory key must agree with the
    // authenticated envelope header before anything is stored.
    let stale_key_blob =
        send_seal(b"unpublished key", &bob_id, &bob_v2_public, None, None).unwrap();
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post(&stale_key_blob, None)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let other = send_seal(b"other", &bob_id, &bob_v1_public, None, None).unwrap();
    let mismatched_id = json!({
        "recipient_id": blob.recipient_id,
        "message_id": other.message_id,
        "blob": blob,
        "expires_at": null,
    });
    let (s, _) = send(&app, "POST", "/send", Some(&alice), Some(mismatched_id)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut malformed = other;
    malformed.eph_pub = B64.encode([0u8; 32]);
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post(&malformed, None)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _) = send(&app, "POST", "/send", Some(&alice), Some(post(&blob, None))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Replay (same message_id) → 409.
    let (s, _) = send(&app, "POST", "/send", Some(&alice), Some(post(&blob, None))).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // A well-formed but unknown recipient remains a 404.
    let unknown_blob = send_seal(b"unknown", &unknown_id, &bob_v1_public, None, None).unwrap();
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post(&unknown_blob, None)),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Expired or excessively long-lived messages are rejected at ingestion.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expired = send_seal(b"expired", &bob_id, &bob_v1_public, None, None).unwrap();
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post(&expired, Some(now - 1))),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let too_long = send_seal(b"too long", &bob_id, &bob_v1_public, None, None).unwrap();
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post(&too_long, Some(now + 8 * 24 * 60 * 60))),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Bob's inbox has the valid envelope only; Alice's inbox is empty.
    let (s, inbox) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<&str> = inbox
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![blob.message_id.as_str()]);
    let (_s, ainbox) = send(&app, "GET", "/send/inbox", Some(&alice), None).await;
    assert_eq!(ainbox.as_array().unwrap().len(), 0);

    // Bob reads-once: delete the canonical message id.
    let message_path = blob
        .message_id
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    let (s, _) = send(
        &app,
        "DELETE",
        &format!("/send/inbox/{message_path}"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_s, inbox) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(inbox.as_array().unwrap().len(), 0);

    // Oversized blob → 413.
    let mut oversized = send_seal(b"large", &bob_id, &bob_v1_public, None, None).unwrap();
    oversized.body.ct = "A".repeat(300 * 1024);
    let (s, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(post(&oversized, None)),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn corrupted_send_persistence_fails_closed() {
    let path = test_db_path("send-corruption");
    let app = server::app_with_db(&path);
    let alice = signup_login(&app, "send-corrupt-alice@example.com").await;
    let bob = signup_login(&app, "send-corrupt-bob@example.com").await;
    let alice_identity = IdentityKeys::generate(1);
    let bob_identity = IdentityKeys::generate(1);

    let (status, bob_response) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&bob),
        Some(serde_json::to_value(bob_identity.public()).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bob_id = bob_response["bastion_id"].as_str().unwrap().to_string();
    let (status, _) = send(
        &app,
        "PUT",
        "/send/identity",
        Some(&alice),
        Some(serde_json::to_value(alice_identity.public()).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let blob = send_seal(
        b"persisted",
        &bob_id,
        &bob_identity.public(),
        None,
        Some((&alice_identity, "ALICE")),
    )
    .unwrap();
    let original_message_id = blob.message_id.clone();
    let blob_json = serde_json::to_string(&blob).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/send",
        Some(&alice),
        Some(json!({
            "recipient_id": bob_id,
            "message_id": blob.message_id,
            "blob": blob,
            "expires_at": null,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Invalid persisted JSON must fail the whole response, never surface as
    // a synthetic null envelope.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE send_inbox SET blob='{' WHERE message_id=?1",
        [&original_message_id],
    )
    .unwrap();
    let (status, _) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // Row routing metadata is re-bound to the decoded envelope on every read.
    conn.execute(
        "UPDATE send_inbox SET blob=?2 WHERE message_id=?1",
        rusqlite::params![original_message_id, blob_json],
    )
    .unwrap();
    let corrupt_message_id = B64.encode([7u8; 16]);
    conn.execute(
        "UPDATE send_inbox SET message_id=?2 WHERE message_id=?1",
        rusqlite::params![original_message_id, corrupt_message_id],
    )
    .unwrap();
    let (status, _) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    conn.execute(
        "UPDATE send_inbox SET message_id=?2 WHERE message_id=?1",
        rusqlite::params![corrupt_message_id, original_message_id],
    )
    .unwrap();

    // Invalid timestamp state is rejected rather than silently hidden by the
    // active-row query.
    conn.execute(
        "UPDATE send_inbox SET expires_at=created_at + 604801 WHERE message_id=?1",
        [&original_message_id],
    )
    .unwrap();
    let (status, _) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // Purge failures propagate and leave the row intact. Once the injected
    // failure is removed, the valid expired row is deleted normally.
    conn.execute(
        "UPDATE send_inbox SET created_at=1, expires_at=2 WHERE message_id=?1",
        [&original_message_id],
    )
    .unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_send_purge BEFORE DELETE ON send_inbox
         BEGIN SELECT RAISE(ABORT, 'forced purge failure'); END;",
    )
    .unwrap();
    let (status, _) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM send_inbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(remaining, 1);
    conn.execute_batch("DROP TRIGGER reject_send_purge;")
        .unwrap();
    let (status, inbox) = send(&app, "GET", "/send/inbox", Some(&bob), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inbox, json!([]));

    // Corrupted directory persistence also fails closed instead of returning
    // an invented or partial public identity.
    conn.execute(
        "UPDATE send_directory SET public='{}' WHERE email='send-corrupt-bob@example.com'",
        [],
    )
    .unwrap();
    let (status, _) = send(&app, "GET", "/send/whoami", Some(&bob), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, _) = send(
        &app,
        "GET",
        &format!("/send/directory/{bob_id}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    drop(conn);
    drop(app);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[tokio::test]
async fn rate_limits_prelogin_globally_and_per_account() {
    let app = server::app_in_memory_with_auth_rate_limits(server::AuthRateLimits {
        max_entries: 16,
        window: std::time::Duration::from_secs(60),
        account_creations_global: 10,
        account_creations_per_account: 2,
        login_attempts_global: 10,
        login_attempts_per_account: 10,
        prelogins_global: 3,
        prelogins_per_account: 1,
    });
    let (_, registration, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "prelogin-alice@example.com",
            "registration": serde_json::to_value(registration).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // First lookup for the account is allowed.
    let (status, _) = send(
        &app,
        "GET",
        "/accounts/prelogin-alice@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second lookup for the same account trips the per-account limiter.
    let (status, _) = send(
        &app,
        "GET",
        "/accounts/prelogin-alice@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Probing a different (unknown) address consumes the remaining global
    // allowance and is rejected — enumeration cannot proceed at line rate.
    let (status, _) = send(
        &app,
        "GET",
        "/accounts/prelogin-bob@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK); // decoy — still consumes the global allowance
    let (status, _) = send(
        &app,
        "GET",
        "/accounts/prelogin-carol@example.com/prelogin",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn security_headers_are_stamped_on_success_and_error_responses() {
    let app = server::app_in_memory();
    for (method, uri, auth) in [
        ("GET", "/health", None),
        ("GET", "/vault", Some("bogus-token")), // 401
        ("GET", "/accounts/nobody@example.com/prelogin", None), // 404
    ] {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = auth {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = response.headers().clone();
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(get("cache-control"), "no-store", "{method} {uri}");
        assert_eq!(get("pragma"), "no-cache", "{method} {uri}");
        assert_eq!(get("x-content-type-options"), "nosniff", "{method} {uri}");
        assert_eq!(get("referrer-policy"), "no-referrer", "{method} {uri}");
        assert_eq!(get("x-frame-options"), "DENY", "{method} {uri}");
        assert_eq!(
            get("content-security-policy"),
            "default-src 'none'; frame-ancestors 'none'",
            "{method} {uri}"
        );
        assert_eq!(
            get("permissions-policy"),
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            "{method} {uri}"
        );
        assert_eq!(get("cross-origin-opener-policy"), "same-origin", "{method} {uri}");
        assert_eq!(get("cross-origin-resource-policy"), "same-origin", "{method} {uri}");
        assert_eq!(get("x-permitted-cross-domain-policies"), "none", "{method} {uri}");
    }
}

#[tokio::test]
async fn unknown_account_login_pays_the_same_hashing_cost() {
    let app = server::app_in_memory();
    let (_, registration, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "timing-real@example.com",
            "registration": serde_json::to_value(registration).unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wrong_secret = B64.encode([7u8; 32]);

    // Wrong password for a real account: pays a full Argon2id verification.
    let started = std::time::Instant::now();
    let (status, body) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "timing-real@example.com",
            "auth_secret": wrong_secret
        })),
    )
    .await;
    let wrong_password_elapsed = started.elapsed();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, Value::Null);

    // Unknown account: same status, same body, and now a comparable cost —
    // it verifies against a process-constant dummy hash instead of returning
    // in microseconds (which used to leak account existence via timing).
    let started = std::time::Instant::now();
    let (status, body) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "timing-unknown@example.com",
            "auth_secret": wrong_secret
        })),
    )
    .await;
    let unknown_account_elapsed = started.elapsed();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, Value::Null);

    // Coarse bound (scheduling noise aside): the unknown-account path must run
    // real Argon2id work, not answer instantly. Default params take tens of
    // milliseconds; a quarter of the real-account cost is a safe floor.
    assert!(
        unknown_account_elapsed * 4 >= wrong_password_elapsed,
        "unknown-account login answered too fast: {unknown_account_elapsed:?} vs {wrong_password_elapsed:?}"
    );
}

#[tokio::test]
async fn rate_limits_authenticated_vault_and_inbox_reads() {
    let app = server::app_in_memory();
    let token = signup_login(&app, "read-limits@example.com").await;

    // Vault reads: allowed up to the per-minute cap, then throttled.
    for i in 0..60 {
        let (status, _) = send(&app, "GET", "/vault", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK, "vault read {i}");
    }
    let (status, _) = send(&app, "GET", "/vault", Some(&token), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Inbox reads: same shape once an identity is published.
    let identity = IdentityKeys::generate(1);
    let public = serde_json::to_value(identity.public()).unwrap();
    let (status, _) = send(&app, "PUT", "/send/identity", Some(&token), Some(public)).await;
    assert_eq!(status, StatusCode::OK);
    for i in 0..60 {
        let (status, _) = send(&app, "GET", "/send/inbox", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK, "inbox read {i}");
    }
    let (status, _) = send(&app, "GET", "/send/inbox", Some(&token), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn request_bodies_reject_unknown_fields() {
    let app = server::app_in_memory();
    let token = signup_login(&app, "strict-dto@example.com").await;

    // A typo like "expire_at" must fail loudly, not silently store a message
    // the sender believes is ephemeral with no expiry at all.
    let (status, _) = send(
        &app,
        "POST",
        "/send",
        Some(&token),
        Some(json!({
            "recipient_id": "SOMERECIPIENT",
            "message_id": "m1",
            "blob": { "v": 1, "payload": "AAAA" },
            "expire_at": 123
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (_, registration, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/accounts",
        None,
        Some(json!({
            "email": "strict-dto-2@example.com",
            "registration": serde_json::to_value(registration).unwrap(),
            "admin": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        None,
        Some(json!({
            "email": "strict-dto@example.com",
            "auth_secret": B64.encode([0u8; 32]),
            "remember_me": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = send(
        &app,
        "PUT",
        "/vault/items/i1",
        Some(&token),
        Some(json!({
            "blob": { "v": 1, "nonce": "AAAA", "ct": "AAAA" },
            "overwrite": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

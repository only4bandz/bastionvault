//! Entry point for the zero-knowledge sync server.

#[tokio::main]
async fn main() {
    // Structured logs; level via RUST_LOG (default info). Only non-secret
    // operational data is ever emitted (see the request/error log middleware).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:7777".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind address");
    println!("🔐 zero-knowledge server listening on http://{addr}");
    axum::serve(listener, server::app())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server run");
    println!("shutdown complete");
}

/// Resolves when the process receives Ctrl-C or (on Unix) SIGTERM, so in-flight
/// requests finish and SQLite's WAL is checkpointed cleanly on exit instead of
/// clients getting connection resets on a hard kill.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

//! Point d'entrée du serveur de synchronisation zero-knowledge.

#[tokio::main]
async fn main() {
    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:7777".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind address");
    println!("🔐 zero-knowledge server écoute sur http://{addr}");
    axum::serve(listener, server::app())
        .await
        .expect("server run");
}

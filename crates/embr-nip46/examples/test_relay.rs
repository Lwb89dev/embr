//! Runs the in-process test relay as a standalone process (for manual tests and sandbox checks).
//! `cargo run -p embr-nip46 --features testing --example test_relay` prints `ws://127.0.0.1:<port>`.
#![allow(clippy::print_stdout)]

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let relay =
        embr_nip46::testing::TestRelay::start(embr_nip46::testing::Options::default()).await;
    println!("{}", relay.url());
    std::future::pending::<()>().await;
}

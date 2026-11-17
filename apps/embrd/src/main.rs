//! `embrd` entry point.
#![allow(clippy::print_stdout, clippy::print_stderr)]

fn main() {
    use embrd::{DaemonConfig, log};

    let mut cfg = DaemonConfig::from_environment();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" | "-V" => {
                println!("embrd {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!(
                    "embrd {} — the Embr signer daemon\n\n\
                     USAGE: embrd [--data-dir DIR] [--runtime-dir DIR]\n\n\
                     Sockets: signer.sock (client API) and control.sock in the runtime directory.\n\
                     Environment: EMBR_DATA_DIR, EMBR_RUNTIME_DIR, EMBR_SIGNER_SOCKET, EMBR_CONTROL_SOCKET.\n\
                     Control it with `embrctl` or the Embr desktop app.",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            "--data-dir" => match args.next() {
                Some(p) => cfg.data_dir = p.into(),
                None => return fail("--data-dir needs a value"),
            },
            "--runtime-dir" => match args.next() {
                Some(p) => {
                    let dir: std::path::PathBuf = p.into();
                    cfg.signer_socket = dir.join("signer.sock");
                    cfg.control_socket = dir.join("control.sock");
                    cfg.runtime_dir = dir;
                }
                None => return fail("--runtime-dir needs a value"),
            },
            other => return fail(&format!("unknown argument {other:?}")),
        }
    }

    // Harden *before* any thread exists, so every thread inherits the restrictions.
    let report = embr_platform::harden::harden_process();
    for m in &report.applied {
        log(&format!("hardening: {m}"));
    }
    for (m, why) in &report.failed {
        log(&format!("hardening FAILED: {m}: {why}"));
    }
    cfg.harden = false; // already done above

    // Two worker threads are plenty: the daemon is idle almost all of the time.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&format!("cannot start runtime: {e}")),
    };
    rt.block_on(async move {
        let daemon = match embrd::start(cfg).await {
            Ok(d) => d,
            Err(e) => return fail(&e.to_string()),
        };
        #[cfg(unix)]
        {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => return fail(&format!("cannot install signal handler: {e}")),
                };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log("interrupted"),
                _ = term.recv() => log("terminated"),
                () = daemon.stopped() => {}
            }
        }
        #[cfg(not(unix))]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => log("interrupted"),
            () = daemon.stopped() => {}
        }
        daemon.shutdown().await;
    });
}

fn fail(msg: &str) {
    eprintln!("embrd: {msg}");
    std::process::exit(1);
}

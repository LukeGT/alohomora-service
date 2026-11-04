//! Asks the daemon over its root-only socket for a sudo approval. Exit 0 only if
//! approved. Run by the PAM helper; see `pass_secret_service::sudo_auth`.
//!
//! Reads no environment and takes no arguments: it runs as root on behalf of sudo.

use std::{io::Read, os::unix::net::UnixStream, process::ExitCode};

use pass_secret_service::sudo_auth::{APPROVED, SOCKET_PATH};

fn main() -> ExitCode {
    let Ok(mut stream) = UnixStream::connect(SOCKET_PATH) else {
        return ExitCode::FAILURE;
    };
    let mut reply = Vec::with_capacity(APPROVED.len());
    match stream.read_to_end(&mut reply) {
        Ok(_) if reply == APPROVED => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

//! Root-only approval channel for the sudo PAM helper.
//!
//! The session bus cannot decide sudo: its daemon and socket belong to the
//! unprivileged user, who can replace them and answer `org.freedesktop.secrets`
//! themselves. This socket sits in a directory only root can enter, so a client
//! reaching it is root and the "approved" reply can only come from this daemon.
//!
//! Protocol: connect, then read. The daemon writes [`APPROVED`] once a device
//! has approved and closes without writing it otherwise. Disconnecting cancels
//! the pending request.

use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use jiff::Timestamp;
use log::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::{spawn_blocking, JoinHandle},
};
use zbus::zvariant::Optional;

use crate::{
    auth_gate::AuthGate,
    caller_command,
    dbus_server::SecretAccessor,
    error::{Error, Result},
};

pub const SOCKET_PATH: &str = "/run/alohomora/sudo-auth.sock";
pub const APPROVED: &[u8] = b"APPROVED\n";

/// Selects the sudo policy in `caller_command`, so the approver sees the
/// command being run under sudo rather than this helper.
const CALLER_NAME: &str = "sudo-auth";

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The socket's directory must be a real directory that only this user can
/// enter; otherwise the socket's location proves nothing about its clients.
pub fn verify_private_dir(dir: &Path) -> Result {
    let meta = std::fs::symlink_metadata(dir)?;
    let private =
        meta.is_dir() && meta.uid() == effective_uid() && meta.permissions().mode() & 0o077 == 0;
    if private {
        Ok(())
    } else {
        Err(Error::InvalidState(format!(
            "{} must be a directory owned by uid {} with no group/other access",
            dir.display(),
            effective_uid()
        )))
    }
}

pub fn spawn(auth_gate: AuthGate, socket_path: &Path) -> Result<JoinHandle<()>> {
    let dir = socket_path
        .parent()
        .ok_or_else(|| Error::InvalidState("sudo socket path has no parent".into()))?;
    verify_private_dir(dir)?;
    match std::fs::remove_file(socket_path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
        _ => {}
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    info!(
        "Sudo approval socket listening on {}",
        socket_path.display()
    );

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle_client(auth_gate.clone(), stream));
                }
                Err(err) => {
                    error!("Sudo approval socket accept failed: {err}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }))
}

async fn accessor_for(uid: u32, pid: u32) -> SecretAccessor<'static> {
    let chain = spawn_blocking(move || {
        caller_command::system_command_chain_for_caller(pid, Some(CALLER_NAME))
    })
    .await
    .ok();
    SecretAccessor {
        dbus_name: Optional::from(None),
        uid,
        username: Optional::from(Some("root".to_string())),
        pid,
        process_name: Optional::from(Some(CALLER_NAME.to_string())),
        timestamp: Timestamp::now().as_millisecond(),
        chain,
    }
}

async fn handle_client(auth_gate: AuthGate, mut stream: UnixStream) {
    let cred = match stream.peer_cred() {
        Ok(cred) => cred,
        Err(err) => {
            warn!("Sudo approval: cannot read peer credentials: {err}");
            return;
        }
    };
    if cred.uid() != effective_uid() {
        warn!("Sudo approval: refused client with uid {}", cred.uid());
        return;
    }
    let pid = cred.pid().and_then(|p| u32::try_from(p).ok()).unwrap_or(0);
    let accessor = accessor_for(cred.uid(), pid).await;

    let (mut reader, mut writer) = stream.split();
    let mut byte = [0u8; 1];
    let approval = tokio::select! {
        result = auth_gate.request_secret_key(Some(&accessor)) => result,
        _ = reader.read(&mut byte) => {
            info!("Sudo approval: client for pid {pid} went away; cancelled its request");
            return;
        }
    };
    match approval {
        Ok(_key) => {
            if let Err(err) = writer.write_all(APPROVED).await {
                warn!("Sudo approval: could not answer pid {pid}: {err}");
            }
        }
        Err(err) => warn!("Sudo approval: request for pid {pid} not approved: {err}"),
    }
}

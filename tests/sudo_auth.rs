//! The sudo approval socket against a real local-device approval, using a
//! temporary key dir (never the real one).

mod common;

use std::{
    io::Read,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    time::Duration,
};

use pass_secret_service::{
    auth_gate::{AuthGate, LocalChallenge},
    config::AppConfig,
    http_server, key_store, local_device,
    sudo_auth::{self, APPROVED},
};

fn private_dir(mode: u32) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("alhm_sudo_{}", nanoid::nanoid!()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

fn read_reply(socket: std::path::PathBuf) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let mut reply = Vec::new();
        let mut stream = UnixStream::connect(socket).unwrap();
        stream.read_to_end(&mut reply).unwrap();
        reply
    })
}

async fn wait_for_challenge(gate: &AuthGate) -> LocalChallenge {
    for _ in 0..200 {
        if let Some(challenge) = gate.pending_local_challenges().await.into_iter().next() {
            return challenge;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no challenge was parked");
}

#[test]
fn socket_dir_must_be_private() {
    let open = private_dir(0o755);
    assert!(sudo_auth::verify_private_dir(&open).is_err());
    let private = private_dir(0o700);
    assert!(sudo_auth::verify_private_dir(&private).is_ok());
    let link = private.join("link");
    std::os::unix::fs::symlink(&private, &link).unwrap();
    assert!(sudo_auth::verify_private_dir(&link).is_err());
}

#[tokio::test]
async fn approval_is_reported_only_after_a_device_approves() {
    let key_dir = private_dir(0o700);
    std::env::set_var("ALOHOMORA_KEY_DIR", &key_dir);
    let config = AppConfig {
        domain: "test.example.com".into(),
        external_port: 443,
        internal_port: 0,
        web_service_url: "http://127.0.0.1:9".into(),
        use_relay: false,
        authorization_timeout: Duration::from_secs(30),
    };
    let socket_dir = private_dir(0o700);
    let socket = socket_dir.join("sudo-auth.sock");

    // No device registered: the request fails and the socket closes silently.
    let empty_gate = AuthGate::new(&config, key_store::generate_random_secret_key().unwrap());
    let server = sudo_auth::spawn(empty_gate, &socket).unwrap();
    assert!(read_reply(socket.clone()).await.unwrap().is_empty());
    server.abort();

    // Registered device: no reply until it approves, then the approval marker.
    let device = common::register_local_device(&key_dir, &config).await;
    let gate = AuthGate::new(&config, device.local_key.clone());
    let server = sudo_auth::spawn(gate.clone(), &socket).unwrap();
    let reply = read_reply(socket.clone());
    let challenge = wait_for_challenge(&gate).await;
    assert_eq!(challenge.process_name, "sudo-auth");
    assert!(!reply.is_finished());
    let response = local_device::answer_challenge(&device.device_key, &challenge).unwrap();
    http_server::process_authenticate_request(&gate, response)
        .await
        .unwrap();
    assert_eq!(reply.await.unwrap(), APPROVED);

    // Hanging up cancels the pending request.
    let stream = UnixStream::connect(&socket).unwrap();
    wait_for_challenge(&gate).await;
    drop(stream);
    for _ in 0..100 {
        if gate.pending_request_count().await == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(gate.pending_request_count().await, 0);
    server.abort();

    let _ = std::fs::remove_dir_all(&key_dir);
    let _ = std::fs::remove_dir_all(&socket_dir);
}

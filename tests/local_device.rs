//! End-to-end test of the local (virtual) device flow against a real HTTP
//! server on loopback, using a temporary key dir (never the real one).

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{http::HeaderMap, routing::post, Router};
use pass_secret_service::{
    auth_gate::{AuthGate, LocalChallenge},
    config::AppConfig,
    http_server::{self, KeychainInfo},
    key_store::{self, ServiceIdentity},
    local_device::{self, KdfParams},
};
use uuid::Uuid;

#[tokio::test]
async fn local_device_register_unlock_round_trip() {
    let key_dir = std::env::temp_dir().join(format!("alhm_local_e2e_{}", nanoid::nanoid!()));
    std::fs::create_dir_all(&key_dir).unwrap();
    std::env::set_var("ALOHOMORA_KEY_DIR", &key_dir);

    // Mock notification endpoint: any hit means a notification would have been sent.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_handler = hits.clone();
    let mock = Router::new().route(
        "/send-notification",
        post(move || {
            let hits = hits_handler.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(mock_listener, mock).await.unwrap() });
    std::env::set_var(
        "ALOHOMORA_NOTIFICATION_URL",
        format!("http://{mock_addr}/send-notification"),
    );

    let config = AppConfig {
        domain: "test.example.com".into(),
        external_port: 443,
        internal_port: 19969,
        web_service_url: format!("http://{mock_addr}"),
        use_relay: false,
        authorization_timeout: std::time::Duration::from_secs(60),
    };
    let identity = ServiceIdentity {
        service_uuid: Uuid::new_v4().to_string(),
        service_name: "Test Host".into(),
    };
    key_store::write_service_identity(&key_dir, &identity)
        .await
        .unwrap();
    let local_key = key_store::generate_random_secret_key().unwrap();
    let secret_key = key_store::generate_random_secret_key().unwrap();
    let mut expected_secret = [0u8; 32];
    secret_key.unlock(|k| expected_secret.copy_from_slice(k));

    // Registration through the same path as Android devices (pairing token).
    let token =
        key_store::create_temp_pairing_key(&key_dir, &local_key, &secret_key, &config, &identity)
            .await
            .unwrap();
    let device_key = local_device::generate_device_key().unwrap();
    let device_uuid = Uuid::new_v4();
    let request = local_device::build_register_request(
        &device_uuid,
        KeychainInfo {
            domain: config.domain.clone(),
            port: config.external_port,
            service_uuid: identity.service_uuid.clone(),
            service_name: identity.service_name.clone(),
        },
        &token.value,
        local_device::public_key_info(&device_key).unwrap(),
    );
    http_server::process_register_request(&local_key, request)
        .await
        .unwrap();
    assert!(key_dir
        .join(format!(
            "device-keys/local/{device_uuid}/enc_secret_key.bin"
        ))
        .exists());

    // The password-protected key file lives beside the registration.
    let key_file = local_device::encrypt_private_key(
        &device_key,
        b"emergency password",
        KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    let key_path = local_device::key_file_path(&key_dir, &device_uuid.to_string());
    local_device::write_key_file(&key_path, &key_file).unwrap();
    assert_eq!(
        local_device::find_key_files(&key_dir).unwrap(),
        vec![(device_uuid.to_string(), key_path.clone())]
    );

    // Serve the real router on loopback.
    let auth_gate = AuthGate::new(&config, local_key.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let app = http_server::router(auth_gate.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
    });

    let gate = auth_gate.clone();
    let requester = tokio::spawn(async move { gate.request_secret_key(None).await });

    let client = reqwest::Client::new();
    let url = format!("{server}/alohomora/local/challenges");

    // Forwarded requests are refused even from loopback.
    let resp = client
        .get(&url)
        .header("X-Forwarded-For", "203.0.113.9")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let mut challenges: Vec<LocalChallenge> = Vec::new();
    for _ in 0..100 {
        let resp = client.get(&url).send().await.unwrap();
        assert!(resp.status().is_success());
        challenges = resp.json().await.unwrap();
        if !challenges.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].device_uuid, device_uuid.to_string());

    // Unlock: decrypt key from the password-protected file, answer the challenge.
    let loaded = local_device::read_key_file(&key_path).unwrap();
    assert!(local_device::decrypt_private_key(&loaded, b"wrong").is_err());
    let unlocked = local_device::decrypt_private_key(&loaded, b"emergency password").unwrap();
    let response = local_device::answer_challenge(&unlocked, &challenges[0]).unwrap();
    let resp = client
        .post(format!("{server}/alohomora/authenticate"))
        .json(&response)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let recovered = requester.await.unwrap().unwrap();
    recovered.unlock(|k| assert_eq!(k, &expected_secret));

    // Parked challenge is cleared after completion; no notification was sent.
    assert!(auth_gate.pending_local_challenges().await.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let _ = std::fs::remove_dir_all(&key_dir);
}

#[test]
fn challenge_route_rejects_non_loopback_and_proxied_requests() {
    let loopback: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let loopback6: SocketAddr = "[::1]:5000".parse().unwrap();
    let remote: SocketAddr = "192.0.2.10:5000".parse().unwrap();
    let none = HeaderMap::new();

    assert!(http_server::check_local_challenge_request(&loopback, &none).is_ok());
    assert!(http_server::check_local_challenge_request(&loopback6, &none).is_ok());
    assert!(http_server::check_local_challenge_request(&remote, &none).is_err());

    for header in ["x-forwarded-for", "forwarded", "x-real-ip"] {
        let mut headers = HeaderMap::new();
        headers.insert(header, "198.51.100.1".parse().unwrap());
        assert!(http_server::check_local_challenge_request(&loopback, &headers).is_err());
    }
}

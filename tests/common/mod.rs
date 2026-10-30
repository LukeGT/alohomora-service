//! Helpers shared by integration tests. Everything lives in temporary
//! directories; the real key directory is never touched.

#![allow(dead_code)]

use std::path::Path;

use pass_secret_service::{
    config::AppConfig,
    http_server::{self, KeychainInfo},
    key_store::{self, SecureKey, ServiceIdentity},
    local_device,
};
use rsa::RsaPrivateKey;
use uuid::Uuid;

/// A local (virtual) device registered through the normal pairing flow.
pub struct RegisteredDevice {
    pub local_key: SecureKey,
    pub secret_key: SecureKey,
    pub device_key: RsaPrivateKey,
    pub device_uuid: Uuid,
    pub identity: ServiceIdentity,
}

/// Write a service identity into `key_dir` (which must be the current
/// `ALOHOMORA_KEY_DIR`) and register a local device against it.
pub async fn register_local_device(key_dir: &Path, config: &AppConfig) -> RegisteredDevice {
    let identity = ServiceIdentity {
        service_uuid: Uuid::new_v4().to_string(),
        service_name: "Test Host".into(),
    };
    key_store::write_service_identity(key_dir, &identity)
        .await
        .unwrap();
    let local_key = key_store::generate_random_secret_key().unwrap();
    let secret_key = key_store::generate_random_secret_key().unwrap();

    // Registration through the same path as Android devices (pairing token).
    let token =
        key_store::create_temp_pairing_key(key_dir, &local_key, &secret_key, config, &identity)
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

    RegisteredDevice {
        local_key,
        secret_key,
        device_key,
        device_uuid,
        identity,
    }
}

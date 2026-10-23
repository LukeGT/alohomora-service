use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jiff::Timestamp;
use log::{debug, info, warn};
use rand::rngs::OsRng;
use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::{
    sync::{oneshot, Mutex},
    time,
};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    dbus_server::SecretAccessor,
    error::{Error, Result},
    key_store::{self, SecureKey},
};

pub const CHALLENGE_MAGIC: &[u8; 5] = b"ALHM1";
pub const RESPONSE_MAGIC: &[u8; 5] = b"ALHR1";
pub const CHALLENGE_PLAINTEXT_LEN: usize = 137;
pub const RESPONSE_PLAINTEXT_LEN: usize = 105;

pub fn create_challenge_plaintext(
    request_uuid: &Uuid,
    ephemeral_spki_der: &[u8],
    locally_encrypted_secret_key: &[u8],
) -> Result<Vec<u8>> {
    if locally_encrypted_secret_key.len() != 84 {
        return Err(Error::EncryptionError(
            "locally_encrypted_secret_key must be exactly 84 bytes",
        ));
    }
    let ephem_pk_sha256 = Sha256::digest(ephemeral_spki_der);
    let mut challenge = Vec::with_capacity(CHALLENGE_PLAINTEXT_LEN);
    challenge.extend_from_slice(CHALLENGE_MAGIC);
    challenge.extend_from_slice(request_uuid.as_bytes());
    challenge.extend_from_slice(&ephem_pk_sha256);
    challenge.extend_from_slice(locally_encrypted_secret_key);
    Ok(challenge)
}

pub fn create_response_plaintext(
    request_uuid: &Uuid,
    locally_encrypted_secret_key: &[u8],
) -> Result<Vec<u8>> {
    if locally_encrypted_secret_key.len() != 84 {
        return Err(Error::EncryptionError(
            "locally_encrypted_secret_key must be exactly 84 bytes",
        ));
    }
    let mut response = Vec::with_capacity(RESPONSE_PLAINTEXT_LEN);
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(request_uuid.as_bytes());
    response.extend_from_slice(locally_encrypted_secret_key);
    Ok(response)
}

pub fn parse_and_validate_response<'a>(
    decrypted: &'a [u8],
    expected_uuid: &Uuid,
) -> Result<&'a [u8]> {
    if decrypted.len() != RESPONSE_PLAINTEXT_LEN {
        return Err(Error::InvalidRequest(format!(
            "response payload length {} does not match expected {}",
            decrypted.len(),
            RESPONSE_PLAINTEXT_LEN
        )));
    }
    if &decrypted[0..5] != RESPONSE_MAGIC {
        return Err(Error::InvalidRequest(
            "invalid response magic in authentication response".into(),
        ));
    }
    if &decrypted[5..21] != expected_uuid.as_bytes() {
        return Err(Error::InvalidRequest(
            "request_uuid mismatch in authentication response".into(),
        ));
    }
    Ok(&decrypted[21..])
}

#[derive(Clone)]
pub struct AuthGate {
    inner: Arc<AuthGateInner>,
}

impl fmt::Debug for AuthGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthGate")
            .field("domain", &self.inner.domain)
            .field("external_port", &self.inner.external_port)
            .finish_non_exhaustive()
    }
}

struct PendingAuth {
    sender: oneshot::Sender<SecureKey>,
    ephemeral_private_key: RsaPrivateKey,
}

struct AuthGateInner {
    local_key: SecureKey,
    domain: String,
    external_port: u16,
    web_service_url: String,
    notification_url: String,
    use_relay: bool,
    authorization_timeout: Duration,
    pending: Mutex<HashMap<String, PendingAuth>>,
}

#[derive(Debug, Serialize)]
struct AndroidAuthPayload {
    request_uuid: String,
    encrypted_blob: String,
    ephemeral_public_key: String,
    uid: String,
    username: String,
    pid: String,
    process_name: String,
    access_timestamp_ms: String,
    domain: String,
    port: String,
    service_uuid: String,
    service_name: String,
}

impl AuthGate {
    pub fn new(config: &AppConfig, local_key: SecureKey) -> Self {
        Self {
            inner: Arc::new(AuthGateInner {
                local_key,
                domain: config.domain.clone(),
                external_port: config.external_port,
                web_service_url: config.web_service_url.clone(),
                notification_url: config.notification_url(),
                use_relay: config.use_relay,
                authorization_timeout: config.authorization_timeout,
                pending: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn local_key(&self) -> &SecureKey {
        &self.inner.local_key
    }

    pub async fn request_secret_key(
        &self,
        accessor: Option<&SecretAccessor<'_>>,
    ) -> Result<SecureKey> {
        let default_accessor;
        let accessor = match accessor {
            Some(a) => a,
            None => {
                default_accessor = SecretAccessor::for_current_process();
                &default_accessor
            }
        };

        let devices = key_store::list_android_device_auth_blobs().await?;
        if devices.is_empty() {
            warn!("Secret access requested but no Android devices are registered");
            return Err(Error::PermissionDenied);
        }

        let key_dir = key_store::get_key_dir();
        let service_identity = key_store::read_service_identity(&key_dir)
            .await?
            .ok_or_else(|| {
                Error::InvalidState("service identity not initialized; run alohomora-setup".into())
            })?;

        let request_uuid = Uuid::new_v4();
        let request_uuid_str = request_uuid.to_string();

        let mut rng = OsRng;
        let ephemeral_private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|_| Error::EncryptionError("failed to generate ephemeral RSA key"))?;
        let ephemeral_public_key_spki =
            ephemeral_private_key
                .to_public_key()
                .to_public_key_der()
                .map_err(|_| Error::EncryptionError("failed to encode ephemeral public key"))?;
        let ephemeral_public_key_b64 = BASE64.encode(ephemeral_public_key_spki.as_bytes());

        let (sender, receiver) = oneshot::channel();

        {
            let mut pending = self.inner.pending.lock().await;
            pending.insert(
                request_uuid_str.clone(),
                PendingAuth {
                    sender,
                    ephemeral_private_key,
                },
            );
        }

        if self.inner.use_relay {
            let auth_gate = self.clone();
            let web_service_url = self.inner.web_service_url.clone();
            let session_id = request_uuid_str.clone();
            let authorization_timeout = self.inner.authorization_timeout;
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let res = crate::http_server::poll_relay_once(
                    &client,
                    &web_service_url,
                    "authenticate",
                    &session_id,
                    authorization_timeout,
                    |req: crate::http_server::AuthenticateRequest| async move {
                        crate::http_server::process_authenticate_request(&auth_gate, req).await
                    },
                )
                .await;
                if let Err(err) = res {
                    debug!("Relay authenticate poll ended: {err}");
                }
            });
        }

        for device in devices {
            // Decrypt the device registration to retrieve the FCM token and public key
            let registration = match key_store::read_android_device_registration(
                &device.device_uuid,
                &self.inner.local_key,
            )
            .await
            {
                Ok(reg) => reg,
                Err(err) => {
                    warn!(
                        "Failed to read registration for device {}: {}",
                        device.device_uuid, err
                    );
                    continue;
                }
            };

            let fcm_token = match registration["fcm"]["token"].as_str() {
                Some(t) => t.to_string(),
                None => {
                    warn!(
                        "FCM token not found in registration for device {}",
                        device.device_uuid
                    );
                    continue;
                }
            };

            let public_key_info: crate::http_server::PublicKeyInfo =
                match serde_json::from_value(registration["public_key"].clone()) {
                    Ok(pk) => pk,
                    Err(err) => {
                        warn!(
                            "Invalid public key in registration for device {}: {}",
                            device.device_uuid, err
                        );
                        continue;
                    }
                };

            // Construct 137-byte challenge plaintext
            let challenge_plaintext = match device.encrypted_secret_key.unlock_slice(|enc_key| {
                create_challenge_plaintext(
                    &request_uuid,
                    ephemeral_public_key_spki.as_bytes(),
                    enc_key,
                )
            }) {
                Ok(c) => c,
                Err(err) => {
                    warn!(
                        "Failed to construct challenge plaintext for device {}: {}",
                        device.device_uuid, err
                    );
                    continue;
                }
            };

            let encrypted_challenge = match crate::http_server::encrypt_for_device(
                &public_key_info,
                &challenge_plaintext,
            ) {
                Ok(enc) => enc,
                Err(err) => {
                    warn!(
                        "Failed to encrypt challenge for device {}: {}",
                        device.device_uuid, err
                    );
                    continue;
                }
            };

            let encrypted_blob =
                encrypted_challenge.unlock_slice(|encrypted| BASE64.encode(encrypted));

            let domain = registration["keychain"]["domain"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or(&self.inner.domain)
                .to_string();

            let port = if let Some(p) = registration["keychain"]["port"].as_u64() {
                p.to_string()
            } else if let Some(p) = registration["keychain"]["port"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                p.to_string()
            } else {
                self.inner.external_port.to_string()
            };

            let payload = Self::build_auth_payload(
                &request_uuid_str,
                encrypted_blob,
                ephemeral_public_key_b64.clone(),
                accessor,
                domain.clone(),
                port.clone(),
                &service_identity,
            );

            let request_body = serde_json::json!({
                "token": fcm_token,
                "request_uuid": payload.request_uuid,
                "encrypted_blob": payload.encrypted_blob,
                "ephemeral_public_key": payload.ephemeral_public_key,
                "uid": payload.uid,
                "username": payload.username,
                "pid": payload.pid,
                "process_name": payload.process_name,
                "access_timestamp_ms": payload.access_timestamp_ms,
                "domain": payload.domain,
                "port": payload.port,
                "service_uuid": payload.service_uuid,
                "service_name": payload.service_name,
            });

            let client = reqwest::Client::new();
            let url = &self.inner.notification_url;

            info!(
                "Sending push notification to web service for device: {}",
                device.device_uuid
            );
            match client.post(url).json(&request_body).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        info!(
                            "Successfully sent notification request to web service for device {}",
                            device.device_uuid
                        );
                    } else {
                        warn!(
                            "Web service returned error status when sending notification to device {}: {}",
                            device.device_uuid,
                            resp.status()
                        );
                        if let Ok(text) = resp.text().await {
                            warn!("Response body: {}", text);
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        "Failed to send notification request to web service for device {}: {}",
                        device.device_uuid, err
                    );
                }
            }
        }

        match time::timeout(self.inner.authorization_timeout, receiver).await {
            Ok(Ok(secret_key)) => {
                debug!("Authentication gate opened for request {request_uuid_str}");
                Ok(secret_key)
            }
            Ok(Err(_)) => {
                self.inner.pending.lock().await.remove(&request_uuid_str);
                Err(Error::PermissionDenied)
            }
            Err(_) => {
                self.inner.pending.lock().await.remove(&request_uuid_str);
                warn!("Authentication request {request_uuid_str} timed out");
                Err(Error::PermissionDenied)
            }
        }
    }

    pub async fn complete_authentication(
        &self,
        request_uuid: &str,
        decrypted_blob_b64: &str,
    ) -> Result {
        let pending = self
            .inner
            .pending
            .lock()
            .await
            .remove(request_uuid)
            .ok_or_else(|| Error::InvalidRequest("no pending authentication request".into()))?;

        let ciphertext = BASE64
            .decode(decrypted_blob_b64)
            .map_err(|_| Error::InvalidRequest("decrypted_blob_b64 is not valid base64".into()))?;

        // Decrypt using OAEP with MGF1 SHA-1, falling back to OAEP SHA-256
        let decrypted = pending
            .ephemeral_private_key
            .decrypt(rsa::Oaep::new_with_mgf_hash::<Sha256, Sha1>(), &ciphertext)
            .or_else(|_| {
                pending
                    .ephemeral_private_key
                    .decrypt(rsa::Oaep::new::<Sha256>(), &ciphertext)
            })
            .map_err(|_| {
                Error::EncryptionError("failed to decrypt response with ephemeral private key")
            })?;

        let expected_uuid = Uuid::parse_str(request_uuid)
            .map_err(|_| Error::InvalidRequest("invalid request_uuid".into()))?;

        let locally_encrypted = parse_and_validate_response(&decrypted, &expected_uuid)?;
        let secret_key = key_store::decrypt_aes256_gcm(&self.inner.local_key, locally_encrypted)?;
        let secret_key = SecureKey::try_from(secret_key)
            .map_err(|_| Error::EncryptionError("decrypted secret key must be 32 bytes"))?;

        pending
            .sender
            .send(secret_key)
            .map_err(|_| Error::InvalidRequest("authentication request is no longer active".into()))
    }

    fn build_auth_payload(
        request_uuid: &str,
        encrypted_blob: String,
        ephemeral_public_key: String,
        accessor: &SecretAccessor<'_>,
        domain: String,
        port: String,
        service_identity: &key_store::ServiceIdentity,
    ) -> AndroidAuthPayload {
        let timestamp_ms = if accessor.timestamp > 0 {
            accessor.timestamp
        } else {
            Timestamp::now().as_millisecond()
        };

        AndroidAuthPayload {
            request_uuid: request_uuid.to_string(),
            encrypted_blob,
            ephemeral_public_key,
            uid: accessor.uid.to_string(),
            username: optional_string(accessor.username.as_ref()),
            pid: accessor.pid.to_string(),
            process_name: optional_string(accessor.process_name.as_ref()),
            access_timestamp_ms: timestamp_ms.to_string(),
            domain,
            port,
            service_uuid: service_identity.service_uuid.clone(),
            service_name: service_identity.service_name.clone(),
        }
    }
}

fn optional_string(value: Option<&String>) -> String {
    value.cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_challenge_and_response_plaintext_structure() {
        let request_uuid = Uuid::new_v4();
        let dummy_spki_der = b"dummy-spki-public-key-der-bytes-for-test";
        let dummy_locally_encrypted = [7u8; 84];

        // 1. Create challenge plaintext
        let challenge =
            create_challenge_plaintext(&request_uuid, dummy_spki_der, &dummy_locally_encrypted)
                .unwrap();
        assert_eq!(challenge.len(), CHALLENGE_PLAINTEXT_LEN);
        assert_eq!(&challenge[0..5], CHALLENGE_MAGIC);
        assert_eq!(&challenge[5..21], request_uuid.as_bytes());
        let expected_sha256 = Sha256::digest(dummy_spki_der);
        assert_eq!(&challenge[21..53], expected_sha256.as_slice());
        assert_eq!(&challenge[53..137], &dummy_locally_encrypted);

        // 2. Create response plaintext
        let response = create_response_plaintext(&request_uuid, &dummy_locally_encrypted).unwrap();
        assert_eq!(response.len(), RESPONSE_PLAINTEXT_LEN);
        assert_eq!(&response[0..5], RESPONSE_MAGIC);
        assert_eq!(&response[5..21], request_uuid.as_bytes());
        assert_eq!(&response[21..105], &dummy_locally_encrypted);

        // 3. Validate response parser
        let validated = parse_and_validate_response(&response, &request_uuid).unwrap();
        assert_eq!(validated, &dummy_locally_encrypted);

        // 4. Validate wrong magic rejection
        let mut bad_magic = response.clone();
        bad_magic[0] = b'X';
        assert!(parse_and_validate_response(&bad_magic, &request_uuid).is_err());

        // 5. Validate wrong UUID rejection
        let different_uuid = Uuid::new_v4();
        assert!(parse_and_validate_response(&response, &different_uuid).is_err());

        // 6. Validate truncated response rejection
        assert!(parse_and_validate_response(&response[..100], &request_uuid).is_err());
    }

    #[tokio::test]
    async fn test_full_ephemeral_challenge_response_crypto_flow() {
        let mut rng = OsRng;

        // 1. Setup local key and mock 32-byte secret key
        let mut raw_local_key = [42u8; 32];
        let local_key = SecureKey::from_slice_mut(&mut raw_local_key).unwrap();
        let raw_secret_key = [99u8; 32];
        let locally_encrypted_secret_key =
            key_store::encrypt_aes256_gcm(&local_key, &raw_secret_key).unwrap();

        // Verify locally_encrypted_secret_key is exactly 84 bytes
        locally_encrypted_secret_key.unlock_slice(|bytes| {
            assert_eq!(bytes.len(), 84);
        });

        // 2. Setup mock registered device with RSA-2048 key
        let device_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let device_spki = device_private_key
            .to_public_key()
            .to_public_key_der()
            .unwrap();
        let device_pk_info = crate::http_server::PublicKeyInfo {
            algorithm: "RSA-OAEP-256".to_string(),
            format: "X.509 SubjectPublicKeyInfo".to_string(),
            value_b64: BASE64.encode(device_spki.as_bytes()),
            parameters: crate::http_server::PublicKeyParameters {
                digest: "SHA-256".to_string(),
                mgf: "MGF1".to_string(),
                mgf_digest: "SHA-1".to_string(),
            },
        };

        // 3. Server generates ephemeral RSA-2048 key and request_uuid
        let request_uuid = Uuid::new_v4();
        let ephemeral_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let ephemeral_spki = ephemeral_private_key
            .to_public_key()
            .to_public_key_der()
            .unwrap();

        // 4. Server constructs 137-byte challenge plaintext and encrypts for device
        let challenge_plaintext = locally_encrypted_secret_key.unlock_slice(|enc_key| {
            create_challenge_plaintext(&request_uuid, ephemeral_spki.as_bytes(), enc_key).unwrap()
        });
        assert_eq!(challenge_plaintext.len(), CHALLENGE_PLAINTEXT_LEN);

        let encrypted_challenge =
            crate::http_server::encrypt_for_device(&device_pk_info, &challenge_plaintext).unwrap();

        // 5. Device decrypts challenge using device private key
        let decrypted_challenge = encrypted_challenge.unlock_slice(|ciphertext| {
            device_private_key
                .decrypt(
                    Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
                    ciphertext,
                )
                .unwrap()
        });
        assert_eq!(decrypted_challenge.len(), CHALLENGE_PLAINTEXT_LEN);
        assert_eq!(&decrypted_challenge[0..5], CHALLENGE_MAGIC);
        assert_eq!(&decrypted_challenge[5..21], request_uuid.as_bytes());

        // Device verifies Sha256(ephemeral_public_key)
        let expected_ephem_hash = Sha256::digest(ephemeral_spki.as_bytes());
        assert_eq!(&decrypted_challenge[21..53], expected_ephem_hash.as_slice());

        // 6. Device extracts locally_encrypted_secret_key from challenge
        let device_extracted_enc_key = &decrypted_challenge[53..137];

        // 7. Device builds 105-byte response and encrypts to ephemeral_public_key
        let response_plaintext =
            create_response_plaintext(&request_uuid, device_extracted_enc_key).unwrap();
        assert_eq!(response_plaintext.len(), RESPONSE_PLAINTEXT_LEN);

        let ephem_public_key =
            RsaPublicKey::from_public_key_der(ephemeral_spki.as_bytes()).unwrap();
        let response_ciphertext = ephem_public_key
            .encrypt(
                &mut rng,
                Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
                &response_plaintext,
            )
            .unwrap();

        // 8. Server decrypts response with ephemeral_private_key
        let server_decrypted_response = ephemeral_private_key
            .decrypt(
                Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
                &response_ciphertext,
            )
            .unwrap();

        let extracted_locally_enc =
            parse_and_validate_response(&server_decrypted_response, &request_uuid).unwrap();

        // 9. Server decrypts locally_encrypted_secret_key using local_key
        let recovered_secret_key =
            key_store::decrypt_aes256_gcm(&local_key, extracted_locally_enc).unwrap();

        recovered_secret_key.unlock_slice(|recovered| {
            assert_eq!(recovered, &raw_secret_key);
        });
    }

    #[tokio::test]
    async fn test_auth_gate_complete_authentication_flow() {
        let mut rng = OsRng;
        let mut raw_local_key = [17u8; 32];
        let local_key = SecureKey::from_slice_mut(&mut raw_local_key).unwrap();
        let config = AppConfig {
            domain: "test.example.com".to_string(),
            external_port: 443,
            internal_port: 19969,
            web_service_url: "https://alohomora.app".to_string(),
            use_relay: false,
            authorization_timeout: std::time::Duration::from_secs(60),
        };

        let auth_gate = AuthGate::new(&config, local_key.clone());

        let request_uuid = Uuid::new_v4();
        let request_uuid_str = request_uuid.to_string();

        let (sender, receiver) = oneshot::channel();
        let ephemeral_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let ephemeral_spki = ephemeral_private_key
            .to_public_key()
            .to_public_key_der()
            .unwrap();

        {
            let mut pending = auth_gate.inner.pending.lock().await;
            pending.insert(
                request_uuid_str.clone(),
                PendingAuth {
                    sender,
                    ephemeral_private_key,
                },
            );
        }

        // Prepare response with known secret key
        let original_secret_bytes = [88u8; 32];
        let locally_encrypted =
            key_store::encrypt_aes256_gcm(&local_key, &original_secret_bytes).unwrap();
        let response_plaintext = locally_encrypted
            .unlock_slice(|enc_key| create_response_plaintext(&request_uuid, enc_key).unwrap());

        let ephem_public_key =
            RsaPublicKey::from_public_key_der(ephemeral_spki.as_bytes()).unwrap();
        let response_ciphertext = ephem_public_key
            .encrypt(
                &mut rng,
                Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
                &response_plaintext,
            )
            .unwrap();
        let response_b64 = BASE64.encode(&response_ciphertext);

        // First completion should succeed
        assert!(auth_gate
            .complete_authentication(&request_uuid_str, &response_b64)
            .await
            .is_ok());

        let received_key = receiver.await.unwrap();
        received_key.unlock(|key_bytes| {
            assert_eq!(key_bytes, &original_secret_bytes);
        });

        // Replay attempt should fail (single-use ephemeral key)
        let replay_result = auth_gate
            .complete_authentication(&request_uuid_str, &response_b64)
            .await;
        assert!(replay_result.is_err());
    }

    #[tokio::test]
    async fn test_request_secret_key_fails_when_service_identity_missing() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_auth_gate_no_id_{}", nanoid::nanoid!()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let original_key_dir = std::env::var("ALOHOMORA_KEY_DIR").ok();
        std::env::set_var("ALOHOMORA_KEY_DIR", &temp_dir);

        let mut raw_local_key = [17u8; 32];
        let local_key = SecureKey::from_slice_mut(&mut raw_local_key).unwrap();
        let config = AppConfig {
            domain: "test.example.com".to_string(),
            external_port: 443,
            internal_port: 19969,
            web_service_url: "https://alohomora.app".to_string(),
            use_relay: false,
            authorization_timeout: std::time::Duration::from_secs(60),
        };
        let auth_gate = AuthGate::new(&config, local_key.clone());

        // Create a dummy registered device so devices.is_empty() passes
        let dummy_blob = key_store::secure_blob_from_vec(vec![0u8; 84]).unwrap();
        key_store::store_android_device_registration("dummy-dev-uuid", &dummy_blob, &dummy_blob)
            .await
            .unwrap();

        let err = match auth_gate.request_secret_key(None).await {
            Ok(_) => panic!("expected request_secret_key to fail, but it succeeded"),
            Err(e) => e,
        };
        match err {
            Error::InvalidState(msg) => {
                assert_eq!(msg, "service identity not initialized; run alohomora-setup");
            }
            other => panic!("expected Error::InvalidState, got {:?}", other),
        }

        if let Some(val) = original_key_dir {
            std::env::set_var("ALOHOMORA_KEY_DIR", val);
        } else {
            std::env::remove_var("ALOHOMORA_KEY_DIR");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_new_uses_configured_authorization_timeout() {
        let mut raw_local_key = [3u8; 32];
        let local_key = SecureKey::from_slice_mut(&mut raw_local_key).unwrap();
        let config = AppConfig {
            domain: "test.example.com".to_string(),
            external_port: 443,
            internal_port: 19969,
            web_service_url: "https://alohomora.app".to_string(),
            use_relay: false,
            authorization_timeout: Duration::from_secs(3600),
        };
        let auth_gate = AuthGate::new(&config, local_key);
        assert_eq!(
            auth_gate.inner.authorization_timeout,
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_build_auth_payload_with_current_process_accessor() {
        let accessor = SecretAccessor::for_current_process();
        let service_identity = key_store::ServiceIdentity {
            service_uuid: "svc-uuid-123".to_string(),
            service_name: "My Host".to_string(),
        };

        let payload = AuthGate::build_auth_payload(
            "req-uuid-1",
            "blob".to_string(),
            "pubkey".to_string(),
            &accessor,
            "example.com".to_string(),
            "443".to_string(),
            &service_identity,
        );

        assert_eq!(payload.request_uuid, "req-uuid-1");
        assert_eq!(payload.pid, std::process::id().to_string());
        assert_eq!(payload.uid, unsafe { libc::getuid() }.to_string());
        assert!(!payload.username.is_empty());
        assert!(!payload.process_name.is_empty());
        let ts: i64 = payload.access_timestamp_ms.parse().unwrap();
        assert!(ts > 0);
        assert_eq!(payload.service_uuid, "svc-uuid-123");
        assert_eq!(payload.service_name, "My Host");
    }

    #[test]
    fn test_build_auth_payload_with_unknown_caller_accessor() {
        let accessor = SecretAccessor::for_unknown_caller();
        let service_identity = key_store::ServiceIdentity {
            service_uuid: "svc-uuid-456".to_string(),
            service_name: "My Host".to_string(),
        };

        let payload = AuthGate::build_auth_payload(
            "req-uuid-2",
            "blob".to_string(),
            "pubkey".to_string(),
            &accessor,
            "example.com".to_string(),
            "443".to_string(),
            &service_identity,
        );

        assert_eq!(payload.request_uuid, "req-uuid-2");
        assert_eq!(payload.pid, "0");
        assert_eq!(payload.uid, "0");
        assert!(payload.username.is_empty());
        assert!(payload.process_name.is_empty());
        let ts: i64 = payload.access_timestamp_ms.parse().unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn test_build_auth_payload_with_zero_timestamp_falls_back_to_now() {
        let accessor = SecretAccessor::default(); // default has timestamp 0
        assert_eq!(accessor.timestamp, 0);

        let service_identity = key_store::ServiceIdentity {
            service_uuid: "svc-uuid-789".to_string(),
            service_name: "My Host".to_string(),
        };

        let before = Timestamp::now().as_millisecond();
        let payload = AuthGate::build_auth_payload(
            "req-uuid-3",
            "blob".to_string(),
            "pubkey".to_string(),
            &accessor,
            "example.com".to_string(),
            "443".to_string(),
            &service_identity,
        );
        let after = Timestamp::now().as_millisecond();

        let ts: i64 = payload.access_timestamp_ms.parse().unwrap();
        assert!(ts >= before && ts <= after);
    }
}

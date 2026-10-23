use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{debug, error, info};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, sha2::Sha256, Oaep, RsaPublicKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{
    auth_gate::{AuthGate, LocalChallenge},
    config::AppConfig,
    error::{Error, Result},
    key_store::{self, SecureBlob},
};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeychainInfo {
    pub domain: String,
    pub port: u16,
    pub service_uuid: String,
    pub service_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyParameters {
    pub digest: String,
    pub mgf: String,
    pub mgf_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyInfo {
    pub algorithm: String,
    pub format: String,
    pub value_b64: String,
    pub parameters: PublicKeyParameters,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FcmInfo {
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppInfo {
    pub package_name: String,
    pub version_name: String,
    pub version_code: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub os: String,
    pub sdk_int: u32,
    pub release: String,
    pub manufacturer: String,
    pub model: String,
    pub product: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub schema_version: u32,
    pub device_uuid: String,
    pub keychain: KeychainInfo,
    pub device_name: String,
    #[serde(default)]
    pub initialisation_token: Option<String>,
    pub public_key: PublicKeyInfo,
    /// Required for Android devices; absent for local (virtual) devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fcm: Option<FcmInfo>,
    pub app: AppInfo,
    pub device: DeviceInfo,
    pub registered_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticateRequest {
    pub schema_version: u32,
    pub request_uuid: String,
    pub device_uuid: String,
    pub keychain: KeychainInfo,
    pub decrypted_blob_b64: String,
    pub app: AppInfo,
    pub approved_at_ms: i64,
}

#[derive(Clone)]
struct ApiState {
    auth_gate: AuthGate,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidRequest(message) => Self::bad_request(message),
            err => Self::internal(err.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct SetupApiState {
    local_key: key_store::SecureKey,
    done_tx: std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

pub async fn spawn(config: AppConfig, auth_gate: AuthGate) -> Result<JoinHandle<()>> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.internal_port));
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Alohomora HTTP server listening on {} for {}:{}",
        addr, config.domain, config.external_port
    );

    let app = router(auth_gate);

    Ok(tokio::spawn(async move {
        if let Err(err) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            error!("Alohomora HTTP server failed: {err}");
        }
    }))
}

pub fn router(auth_gate: AuthGate) -> Router {
    Router::new()
        .route("/alohomora/authenticate", post(authenticate))
        .route("/alohomora/local/challenges", get(local_challenges))
        .with_state(ApiState { auth_gate })
}

/// Local challenges are only served to direct loopback peers. Any proxy header
/// means the request may have been forwarded (e.g. by a relay running on this
/// host), so it is refused.
pub fn check_local_challenge_request(
    peer: &SocketAddr,
    headers: &HeaderMap,
) -> std::result::Result<(), ApiError> {
    const FORWARDING_HEADERS: [&str; 4] = ["x-forwarded-for", "forwarded", "x-real-ip", "via"];
    if !peer.ip().is_loopback() || FORWARDING_HEADERS.iter().any(|h| headers.contains_key(*h)) {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: "local challenges are only available to direct loopback clients".into(),
        });
    }
    Ok(())
}

async fn local_challenges(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> std::result::Result<Json<Vec<LocalChallenge>>, ApiError> {
    check_local_challenge_request(&peer, &headers)?;
    Ok(Json(state.auth_gate.pending_local_challenges().await))
}

pub async fn spawn_setup_server(
    config: AppConfig,
    local_key: key_store::SecureKey,
    done_tx: std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
) -> Result<JoinHandle<()>> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.internal_port));
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Alohomora Setup HTTP server listening on {} for {}:{}",
        addr, config.domain, config.external_port
    );

    let state = SetupApiState { local_key, done_tx };

    let app = Router::new()
        .route("/alohomora/register", post(register_setup))
        .with_state(state);

    Ok(tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            error!("Alohomora Setup HTTP server failed: {err}");
        }
    }))
}

pub async fn process_register_request(
    local_key: &key_store::SecureKey,
    request: RegisterRequest,
) -> std::result::Result<StatusCode, ApiError> {
    debug!(
        "Received registration request for {}:{} from {} {}",
        request.keychain.domain,
        request.keychain.port,
        request.device.manufacturer,
        request.device.model
    );

    let kind = match request.device.os.as_str() {
        "Android" => {
            if request
                .fcm
                .as_ref()
                .map_or(true, |fcm| fcm.token.is_empty())
            {
                return Err(ApiError::bad_request("fcm.token is required for Android"));
            }
            key_store::DeviceKind::Android
        }
        "Local" => {
            if uuid::Uuid::parse_str(&request.device_uuid).is_err() {
                return Err(ApiError::bad_request("device_uuid must be a UUID"));
            }
            key_store::DeviceKind::Local
        }
        _ => {
            return Err(ApiError::bad_request(
                "only Android and Local registrations are supported",
            ));
        }
    };

    let identity = key_store::read_service_identity(&key_store::get_key_dir())
        .await?
        .ok_or_else(|| {
            ApiError::internal("service identity not initialized; run alohomora-setup")
        })?;

    if request.keychain.service_uuid != identity.service_uuid {
        return Err(ApiError::bad_request(format!(
            "service_uuid mismatch: request specified {}, but service is {}",
            request.keychain.service_uuid, identity.service_uuid
        )));
    }

    let initialisation_token = request
        .initialisation_token
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("initialisation_token is required"))?;

    validate_public_key_info(&request.public_key)?;

    let secret_key = key_store::read_temp_secret_key(initialisation_token, local_key).await?;
    let locally_encrypted_secret_key =
        secret_key.unlock(|secret_key| key_store::encrypt_aes256_gcm(local_key, secret_key))?;

    let registration_json = serde_json::to_vec(&request)
        .map_err(|err| ApiError::internal(format!("failed to serialize registration: {err}")))?;
    let encrypted_registration = key_store::encrypt_aes256_gcm(local_key, &registration_json)?;

    key_store::store_device_registration(
        kind,
        &request.device_uuid,
        &encrypted_registration,
        &locally_encrypted_secret_key,
    )
    .await?;

    key_store::remove_temp_pairing_key(initialisation_token).await?;

    info!(
        "Registered {:?} device {} at device-keys/{}/{}",
        kind,
        request.device.model,
        kind.dir_name(),
        request.device_uuid
    );

    Ok(StatusCode::NO_CONTENT)
}

async fn register_setup(
    State(state): State<SetupApiState>,
    Json(request): Json<RegisterRequest>,
) -> std::result::Result<StatusCode, ApiError> {
    let status = process_register_request(&state.local_key, request).await?;

    if let Some(tx) = state.done_tx.lock().await.take() {
        let _ = tx.send(());
    }

    Ok(status)
}

pub async fn process_authenticate_request(
    auth_gate: &AuthGate,
    request: AuthenticateRequest,
) -> std::result::Result<StatusCode, ApiError> {
    let identity = key_store::read_service_identity(&key_store::get_key_dir())
        .await?
        .ok_or_else(|| {
            ApiError::internal("service identity not initialized; run alohomora-setup")
        })?;

    if request.keychain.service_uuid != identity.service_uuid {
        return Err(ApiError::bad_request(format!(
            "service_uuid mismatch: request specified {}, but service is {}",
            request.keychain.service_uuid, identity.service_uuid
        )));
    }

    debug!(
        "Received authentication approval for request {} from {} on device {}",
        request.request_uuid, request.app.package_name, request.device_uuid
    );
    let local_challenge = auth_gate
        .find_local_challenge(&request.request_uuid, &request.device_uuid)
        .await;
    auth_gate
        .complete_authentication(&request.request_uuid, &request.decrypted_blob_b64)
        .await?;
    if let Some(challenge) = local_challenge {
        info!(
            "Local device unlock approved: device {} ({}), request {}, requested by uid={} user={} pid={} process={}",
            challenge.device_uuid,
            challenge.device_name,
            challenge.request_uuid,
            challenge.uid,
            challenge.username,
            challenge.pid,
            challenge.process_name,
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate(
    State(state): State<ApiState>,
    Json(request): Json<AuthenticateRequest>,
) -> std::result::Result<StatusCode, ApiError> {
    process_authenticate_request(&state.auth_gate, request).await
}

pub async fn poll_relay_once<T, F, Fut>(
    client: &reqwest::Client,
    web_service_url: &str,
    channel: &str,
    session_id: &str,
    total_timeout: Duration,
    handler: F,
) -> Result<()>
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(T) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<StatusCode, ApiError>>,
{
    let base = web_service_url.trim_end_matches('/');
    let poll_url = format!("{base}/alohomora/relay/{channel}/{session_id}/poll");
    let complete_url = format!("{base}/alohomora/relay/{channel}/{session_id}/complete");

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut handler_opt = Some(handler);

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let resp_result = client.get(&poll_url).timeout(remaining).send().await;
        let resp = match resp_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Relay poll network error on {poll_url}: {e}");
                let sleep_dur = Duration::from_secs(1)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                if !sleep_dur.is_zero() {
                    tokio::time::sleep(sleep_dur).await;
                }
                continue;
            }
        };

        let status = resp.status();
        if status == StatusCode::NO_CONTENT {
            continue;
        }

        if status == StatusCode::OK {
            let payload: T = match resp.json().await {
                Ok(p) => p,
                Err(e) => {
                    let err_msg = format!("failed to deserialize relay payload: {e}");
                    log::warn!("{err_msg}");
                    let _ = client
                        .post(&complete_url)
                        .json(&serde_json::json!({
                            "status": StatusCode::BAD_REQUEST.as_u16(),
                            "message": err_msg,
                        }))
                        .send()
                        .await;
                    return Err(Error::InvalidRequest(err_msg));
                }
            };

            let handler = match handler_opt.take() {
                Some(h) => h,
                None => {
                    return Err(Error::InvalidRequest(
                        "relay handler already consumed".into(),
                    ));
                }
            };

            let handler_result = handler(payload).await;
            let complete_body = match &handler_result {
                Ok(status) => serde_json::json!({
                    "status": status.as_u16(),
                }),
                Err(err) => serde_json::json!({
                    "status": err.status.as_u16(),
                    "message": err.message,
                }),
            };

            if let Err(post_err) = client.post(&complete_url).json(&complete_body).send().await {
                log::warn!("Failed to send relay completion to {complete_url}: {post_err}");
            }

            return match handler_result {
                Ok(_) => Ok(()),
                Err(err) => Err(Error::InvalidRequest(err.message)),
            };
        }

        log::warn!("Unexpected status {status} from relay poll on {poll_url}");
        let sleep_dur = Duration::from_secs(1)
            .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        if !sleep_dur.is_zero() {
            tokio::time::sleep(sleep_dur).await;
        }
    }

    Err(Error::InvalidRequest("relay polling timed out".into()))
}

pub(crate) fn validate_public_key_info(
    public_key: &PublicKeyInfo,
) -> std::result::Result<(), ApiError> {
    if public_key.algorithm != "RSA-OAEP-256" {
        return Err(ApiError::bad_request(
            "public_key.algorithm must be RSA-OAEP-256",
        ));
    }
    if public_key.format != "X.509 SubjectPublicKeyInfo" {
        return Err(ApiError::bad_request(
            "public_key.format must be X.509 SubjectPublicKeyInfo",
        ));
    }
    if public_key.parameters.digest != "SHA-256"
        || public_key.parameters.mgf != "MGF1"
        || !matches!(
            public_key.parameters.mgf_digest.as_str(),
            "SHA-1" | "SHA-256"
        )
    {
        return Err(ApiError::bad_request(
            "public_key.parameters must specify SHA-256/MGF1/(SHA-1 or SHA-256)",
        ));
    }
    Ok(())
}

pub(crate) fn encrypt_for_device(
    public_key: &PublicKeyInfo,
    plaintext: &[u8],
) -> std::result::Result<SecureBlob, ApiError> {
    let public_key_der = BASE64
        .decode(&public_key.value_b64)
        .map_err(|_| ApiError::bad_request("public_key.value_b64 is not valid base64"))?;
    let rsa_key = RsaPublicKey::from_public_key_der(&public_key_der)
        .map_err(|_| ApiError::bad_request("public_key.value_b64 is not a valid SPKI RSA key"))?;

    let encrypted = if public_key.parameters.mgf_digest == "SHA-256" {
        rsa_key.encrypt(&mut OsRng, Oaep::new::<Sha256>(), plaintext)
    } else {
        rsa_key.encrypt(
            &mut OsRng,
            Oaep::new_with_mgf_hash::<Sha256, sha1::Sha1>(),
            plaintext,
        )
    }
    .map_err(|err| ApiError::bad_request(format!("RSA-OAEP-256 encryption failed: {err}")))?;

    key_store::secure_blob_from_vec(encrypted).map_err(ApiError::from)
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::{AuthenticateRequest, RegisterRequest};

    #[test]
    fn register_request_has_json_schema() {
        let schema = schema_for!(RegisterRequest);
        assert_eq!(
            schema.schema.metadata.unwrap().title.unwrap(),
            "RegisterRequest"
        );
    }

    #[test]
    fn authenticate_request_has_json_schema() {
        let schema = schema_for!(AuthenticateRequest);
        assert_eq!(
            schema.schema.metadata.unwrap().title.unwrap(),
            "AuthenticateRequest"
        );
    }

    #[test]
    fn register_request_parses_expected_payload() {
        let payload = r#"{
            "schema_version": 1,
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443,
              "service_uuid": "11111111-2222-3333-4444-555555555555",
              "service_name": "Host Alpha"
            },
            "device_name": "Pixel 9",
            "initialisation_token": "optional-token",
            "public_key": {
              "algorithm": "RSA-OAEP-256",
              "format": "X.509 SubjectPublicKeyInfo",
              "value_b64": "base64-public-key",
              "parameters": {
                "digest": "SHA-256",
                "mgf": "MGF1",
                "mgf_digest": "SHA-256"
              }
            },
            "fcm": {
              "token": "firebase-registration-token"
            },
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "device": {
              "os": "Android",
              "sdk_int": 36,
              "release": "16",
              "manufacturer": "Google",
              "model": "Pixel",
              "product": "pixel"
            },
            "registered_at_ms": 1760000000000
        }"#;

        let request: RegisterRequest = serde_json::from_str(payload).unwrap();
        assert_eq!(request.schema_version, 1);
        assert_eq!(request.device_uuid, "f2018f87-e926-42a1-8b48-9ad4b7fd7cde");
        assert_eq!(
            request.keychain.service_uuid,
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(request.keychain.service_name, "Host Alpha");
        assert_eq!(
            request.initialisation_token.as_deref(),
            Some("optional-token")
        );
        assert_eq!(request.public_key.parameters.mgf_digest, "SHA-256");
    }

    #[test]
    fn authenticate_request_parses_expected_payload() {
        let payload = r#"{
            "schema_version": 1,
            "request_uuid": "6fbbce84-5aef-43c3-8cc7-469cbfd83109",
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443,
              "service_uuid": "11111111-2222-3333-4444-555555555555",
              "service_name": "Host Alpha"
            },
            "decrypted_blob_b64": "base64-decrypted-blob",
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "approved_at_ms": 1760000000123
        }"#;

        let request: AuthenticateRequest = serde_json::from_str(payload).unwrap();
        assert_eq!(request.schema_version, 1);
        assert_eq!(request.request_uuid, "6fbbce84-5aef-43c3-8cc7-469cbfd83109");
        assert_eq!(request.device_uuid, "f2018f87-e926-42a1-8b48-9ad4b7fd7cde");
        assert_eq!(
            request.keychain.service_uuid,
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(request.keychain.service_name, "Host Alpha");
        assert_eq!(request.decrypted_blob_b64, "base64-decrypted-blob");
    }

    #[test]
    fn test_validate_public_key_info_and_encrypt_for_device_mgf1_sha1() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use rsa::pkcs8::EncodePublicKey;
        use rsa::RsaPrivateKey;

        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let spki_der = public_key.to_public_key_der().unwrap();
        let value_b64 = BASE64.encode(spki_der.as_bytes());

        let pk_info_sha1 = super::PublicKeyInfo {
            algorithm: "RSA-OAEP-256".to_string(),
            format: "X.509 SubjectPublicKeyInfo".to_string(),
            value_b64: value_b64.clone(),
            parameters: super::PublicKeyParameters {
                digest: "SHA-256".to_string(),
                mgf: "MGF1".to_string(),
                mgf_digest: "SHA-1".to_string(),
            },
        };

        // 1. Verify validation succeeds for SHA-1 MGF digest
        assert!(super::validate_public_key_info(&pk_info_sha1).is_ok());

        // 2. Verify encryption with encrypt_for_device succeeds with SHA-1
        let plaintext = b"secret-token-bytes-1234";
        let encrypted = super::encrypt_for_device(&pk_info_sha1, plaintext).unwrap();

        // 3. Verify decryption with OAEP MGF1 SHA-1 recovers original plaintext
        encrypted.unlock_slice(|ciphertext| {
            let decrypted = private_key
                .decrypt(
                    rsa::Oaep::new_with_mgf_hash::<rsa::sha2::Sha256, sha1::Sha1>(),
                    ciphertext,
                )
                .unwrap();
            assert_eq!(decrypted, plaintext);
        });

        // 4. Verify validation also succeeds for SHA-256 MGF digest
        let mut pk_info_sha256 = pk_info_sha1.clone();
        pk_info_sha256.parameters.mgf_digest = "SHA-256".to_string();
        assert!(super::validate_public_key_info(&pk_info_sha256).is_ok());

        // 5. Verify validation rejects invalid MGF digest (e.g. SHA-512)
        let mut pk_info_invalid = pk_info_sha1.clone();
        pk_info_invalid.parameters.mgf_digest = "SHA-512".to_string();
        assert!(super::validate_public_key_info(&pk_info_invalid).is_err());
    }

    struct MockServerState {
        poll_count: std::sync::atomic::AtomicUsize,
        complete_bodies: tokio::sync::Mutex<Vec<serde_json::Value>>,
        payload: serde_json::Value,
    }

    async fn mock_poll(
        axum::extract::Path((_channel, _id)): axum::extract::Path<(String, String)>,
        axum::extract::State(state): axum::extract::State<std::sync::Arc<MockServerState>>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let count = state
            .poll_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if count == 0 {
            axum::http::StatusCode::NO_CONTENT.into_response()
        } else {
            (
                axum::http::StatusCode::OK,
                axum::Json(state.payload.clone()),
            )
                .into_response()
        }
    }

    async fn mock_complete(
        axum::extract::Path((_channel, _id)): axum::extract::Path<(String, String)>,
        axum::extract::State(state): axum::extract::State<std::sync::Arc<MockServerState>>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::http::StatusCode {
        state.complete_bodies.lock().await.push(body);
        axum::http::StatusCode::NO_CONTENT
    }

    #[tokio::test]
    async fn test_poll_relay_once_register_request() {
        let payload_json: serde_json::Value = serde_json::json!({
            "schema_version": 1,
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443,
              "service_uuid": "11111111-2222-3333-4444-555555555555",
              "service_name": "Host Alpha"
            },
            "device_name": "Pixel 9",
            "initialisation_token": "optional-token",
            "public_key": {
              "algorithm": "RSA-OAEP-256",
              "format": "X.509 SubjectPublicKeyInfo",
              "value_b64": "base64-public-key",
              "parameters": {
                "digest": "SHA-256",
                "mgf": "MGF1",
                "mgf_digest": "SHA-256"
              }
            },
            "fcm": {
              "token": "firebase-registration-token"
            },
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "device": {
              "os": "Android",
              "sdk_int": 36,
              "release": "16",
              "manufacturer": "Google",
              "model": "Pixel",
              "product": "pixel"
            },
            "registered_at_ms": 1760000000000_i64
        });

        let state = std::sync::Arc::new(MockServerState {
            poll_count: std::sync::atomic::AtomicUsize::new(0),
            complete_bodies: tokio::sync::Mutex::new(Vec::new()),
            payload: payload_json.clone(),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let app = axum::Router::new()
            .route(
                "/alohomora/relay/:channel/:id/poll",
                axum::routing::get(mock_poll),
            )
            .route(
                "/alohomora/relay/:channel/:id/complete",
                axum::routing::post(mock_complete),
            )
            .with_state(state.clone());

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let handler_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_called_clone = handler_called.clone();

        let res = super::poll_relay_once::<RegisterRequest, _, _>(
            &client,
            &base_url,
            "register",
            "test-pairing-id",
            std::time::Duration::from_secs(5),
            |req: RegisterRequest| async move {
                assert_eq!(req.device_uuid, "f2018f87-e926-42a1-8b48-9ad4b7fd7cde");
                handler_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(axum::http::StatusCode::NO_CONTENT)
            },
        )
        .await;

        assert!(res.is_ok());
        assert!(handler_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            state.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            2
        );

        let completed = state.complete_bodies.lock().await;
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0]["status"], 204);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_poll_relay_once_authenticate_request() {
        let payload_json: serde_json::Value = serde_json::json!({
            "schema_version": 1,
            "request_uuid": "6fbbce84-5aef-43c3-8cc7-469cbfd83109",
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443,
              "service_uuid": "11111111-2222-3333-4444-555555555555",
              "service_name": "Host Alpha"
            },
            "decrypted_blob_b64": "base64-decrypted-blob",
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "approved_at_ms": 1760000000123_i64
        });

        let state = std::sync::Arc::new(MockServerState {
            poll_count: std::sync::atomic::AtomicUsize::new(0),
            complete_bodies: tokio::sync::Mutex::new(Vec::new()),
            payload: payload_json.clone(),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let app = axum::Router::new()
            .route(
                "/alohomora/relay/:channel/:id/poll",
                axum::routing::get(mock_poll),
            )
            .route(
                "/alohomora/relay/:channel/:id/complete",
                axum::routing::post(mock_complete),
            )
            .with_state(state.clone());

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let handler_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_called_clone = handler_called.clone();

        let res = super::poll_relay_once::<AuthenticateRequest, _, _>(
            &client,
            &base_url,
            "authenticate",
            "test-request-uuid",
            std::time::Duration::from_secs(5),
            |req: AuthenticateRequest| async move {
                assert_eq!(req.request_uuid, "6fbbce84-5aef-43c3-8cc7-469cbfd83109");
                handler_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(axum::http::StatusCode::NO_CONTENT)
            },
        )
        .await;

        assert!(res.is_ok());
        assert!(handler_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            state.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            2
        );

        let completed = state.complete_bodies.lock().await;
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0]["status"], 204);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_poll_relay_once_handler_error_reporting() {
        let payload_json: serde_json::Value = serde_json::json!({
            "schema_version": 1,
            "request_uuid": "6fbbce84-5aef-43c3-8cc7-469cbfd83109",
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443,
              "service_uuid": "11111111-2222-3333-4444-555555555555",
              "service_name": "Host Alpha"
            },
            "decrypted_blob_b64": "base64-decrypted-blob",
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "approved_at_ms": 1760000000123_i64
        });

        let state = std::sync::Arc::new(MockServerState {
            poll_count: std::sync::atomic::AtomicUsize::new(1), // return 200 on first poll
            complete_bodies: tokio::sync::Mutex::new(Vec::new()),
            payload: payload_json.clone(),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let app = axum::Router::new()
            .route(
                "/alohomora/relay/:channel/:id/poll",
                axum::routing::get(mock_poll),
            )
            .route(
                "/alohomora/relay/:channel/:id/complete",
                axum::routing::post(mock_complete),
            )
            .with_state(state.clone());

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let res = super::poll_relay_once::<AuthenticateRequest, _, _>(
            &client,
            &base_url,
            "authenticate",
            "test-request-uuid",
            std::time::Duration::from_secs(5),
            |_req: AuthenticateRequest| async move {
                Err(super::ApiError::bad_request(
                    "simulated authorization failure",
                ))
            },
        )
        .await;

        assert!(
            matches!(res, Err(crate::error::Error::InvalidRequest(msg)) if msg == "simulated authorization failure")
        );

        let completed = state.complete_bodies.lock().await;
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0]["status"], 400);
        assert_eq!(completed[0]["message"], "simulated authorization failure");

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_register_request_with_service_uuid_validation() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let temp_dir =
            std::env::temp_dir().join(format!("test_http_key_dir_{}", nanoid::nanoid!()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let original_key_dir = std::env::var("ALOHOMORA_KEY_DIR").ok();
        std::env::set_var("ALOHOMORA_KEY_DIR", &temp_dir);

        let my_identity = crate::key_store::ServiceIdentity {
            service_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            service_name: "Host Alpha".to_string(),
        };
        crate::key_store::write_service_identity(&temp_dir, &my_identity)
            .await
            .unwrap();

        let local_key = crate::key_store::generate_random_secret_key().unwrap();
        let secret_key = crate::key_store::generate_random_secret_key().unwrap();
        let config = crate::config::AppConfig {
            domain: "example.com".to_string(),
            external_port: 443,
            internal_port: 19969,
            web_service_url: "https://alohomora.app".to_string(),
            use_relay: false,
        };

        // Create a temp pairing key so token lookup works
        let token = crate::key_store::create_temp_pairing_key(
            &temp_dir,
            &local_key,
            &secret_key,
            &config,
            &my_identity,
        )
        .await
        .unwrap();

        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let spki =
            rsa::pkcs8::EncodePublicKey::to_public_key_der(&rsa_key.to_public_key()).unwrap();
        let pub_key_b64 = BASE64.encode(spki.as_bytes());

        let req_matching: super::RegisterRequest = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "device_uuid": "dev-123",
            "keychain": {
                "domain": "example.com",
                "port": 443,
                "service_uuid": "11111111-2222-3333-4444-555555555555",
                "service_name": "Host Alpha"
            },
            "device_name": "Android Test",
            "initialisation_token": token.value,
            "public_key": {
                "algorithm": "RSA-OAEP-256",
                "format": "X.509 SubjectPublicKeyInfo",
                "value_b64": pub_key_b64,
                "parameters": {
                    "digest": "SHA-256",
                    "mgf": "MGF1",
                    "mgf_digest": "SHA-256"
                }
            },
            "fcm": {
                "token": "fcm-tok"
            },
            "app": {
                "package_name": "com.alohomora",
                "version_name": "1.0",
                "version_code": 1
            },
            "device": {
                "os": "Android",
                "sdk_int": 34,
                "release": "14",
                "manufacturer": "Google",
                "model": "Pixel",
                "product": "pixel"
            },
            "registered_at_ms": 123456789_i64
        }))
        .unwrap();

        // 1. Mismatched service_uuid should fail with 400 Bad Request
        let mut req_mismatched = req_matching.clone();
        req_mismatched.keychain.service_uuid = "99999999-9999-9999-9999-999999999999".to_string();
        let err = super::process_register_request(&local_key, req_mismatched)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("service_uuid mismatch"));

        // 2. Matching service_uuid should succeed
        let status = super::process_register_request(&local_key, req_matching.clone())
            .await
            .unwrap();
        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);

        // 3. Missing service identity should fail with 500 Internal Server Error
        let empty_temp_dir =
            std::env::temp_dir().join(format!("test_http_key_dir_empty_{}", nanoid::nanoid!()));
        std::fs::create_dir_all(&empty_temp_dir).unwrap();
        std::env::set_var("ALOHOMORA_KEY_DIR", &empty_temp_dir);

        let err = super::process_register_request(&local_key, req_matching)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            err.message,
            "service identity not initialized; run alohomora-setup"
        );
        let _ = std::fs::remove_dir_all(&empty_temp_dir);

        if let Some(val) = original_key_dir {
            std::env::set_var("ALOHOMORA_KEY_DIR", val);
        } else {
            std::env::remove_var("ALOHOMORA_KEY_DIR");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_authenticate_request_with_service_uuid_validation() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_http_auth_key_dir_{}", nanoid::nanoid!()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let original_key_dir = std::env::var("ALOHOMORA_KEY_DIR").ok();
        std::env::set_var("ALOHOMORA_KEY_DIR", &temp_dir);

        let local_key = crate::key_store::generate_random_secret_key().unwrap();
        let config = crate::config::AppConfig {
            domain: "example.com".to_string(),
            external_port: 443,
            internal_port: 19969,
            web_service_url: "https://alohomora.app".to_string(),
            use_relay: false,
        };
        let auth_gate = crate::auth_gate::AuthGate::new(&config, local_key);

        let req: super::AuthenticateRequest = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "request_uuid": "6fbbce84-5aef-43c3-8cc7-469cbfd83109",
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
                "domain": "example.com",
                "port": 443,
                "service_uuid": "11111111-2222-3333-4444-555555555555",
                "service_name": "Host Alpha"
            },
            "decrypted_blob_b64": "base64-decrypted-blob",
            "app": {
                "package_name": "com.alohomora.app",
                "version_name": "0.1.0",
                "version_code": 1
            },
            "approved_at_ms": 1760000000123_i64
        }))
        .unwrap();

        // 1. Missing service identity should fail with 500 Internal Server Error
        let err = super::process_authenticate_request(&auth_gate, req.clone())
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            err.message,
            "service identity not initialized; run alohomora-setup"
        );

        // 2. Write service identity with different service_uuid
        let my_identity = crate::key_store::ServiceIdentity {
            service_uuid: "22222222-3333-4444-5555-666666666666".to_string(),
            service_name: "Host Beta".to_string(),
        };
        crate::key_store::write_service_identity(&temp_dir, &my_identity)
            .await
            .unwrap();

        // Mismatched service_uuid should fail with 400 Bad Request
        let err = super::process_authenticate_request(&auth_gate, req.clone())
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("service_uuid mismatch"));

        // 3. Matching service_uuid should pass service identity validation and proceed to auth_gate
        let mut req_matching = req.clone();
        req_matching.keychain.service_uuid = "22222222-3333-4444-5555-666666666666".to_string();
        let err = super::process_authenticate_request(&auth_gate, req_matching)
            .await
            .unwrap_err();
        // Since no pending auth request was registered with auth_gate, it returns "no pending authentication request"
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "no pending authentication request");

        if let Some(val) = original_key_dir {
            std::env::set_var("ALOHOMORA_KEY_DIR", val);
        } else {
            std::env::remove_var("ALOHOMORA_KEY_DIR");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

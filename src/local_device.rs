//! Password-protected "virtual local device" used for emergency unlocks when no
//! phone is available. It speaks exactly the same ALHM1/ALHR1 protocol as the
//! Android app; only the transport differs (loopback HTTP instead of FCM).
//!
//! The device's RSA-2048 private key lives in
//! `<key dir>/device-keys/local/<device uuid>/private_key.enc.json`, encrypted
//! with a key derived from the user's password (Argon2id + AES-256-GCM).

use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jiff::Timestamp;
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    auth_gate::{
        create_response_plaintext, LocalChallenge, CHALLENGE_MAGIC, CHALLENGE_PLAINTEXT_LEN,
    },
    error::{Error, Result},
    http_server::{
        AppInfo, AuthenticateRequest, DeviceInfo, KeychainInfo, PublicKeyInfo, PublicKeyParameters,
        RegisterRequest,
    },
    key_store::{self, DeviceKind, SecureKey},
};

pub const KEY_FILE_VERSION: u32 = 1;
pub const KDF_NAME: &str = "argon2id";
pub const LOCAL_DEVICE_NAME: &str = "Local Terminal Unlock";
pub const LOCAL_DEVICE_OS: &str = "Local";
const SALT_LEN: usize = 16;
/// Upper bounds on KDF parameters read from a (possibly tampered) key file.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 32;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// On-disk, password-encrypted private key (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    pub version: u32,
    pub kdf: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_b64: String,
    /// `encrypt_aes256_gcm` output over the PKCS#8 DER private key.
    pub encrypted_key_b64: String,
}

fn derive_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<SecureKey> {
    let argon_params = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(key_store::AES256_KEY_BYTES),
    )
    .map_err(|_| Error::EncryptionError("invalid Argon2 parameters"))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut out = [0u8; key_store::AES256_KEY_BYTES];
    let res = argon.hash_password_into(password, salt, &mut out);
    let key = res
        .map_err(|_| Error::EncryptionError("password key derivation failed"))
        .and_then(|_| {
            SecureKey::from_slice_mut(&mut out)
                .map_err(|_| Error::EncryptionError("failed to allocate secure key"))
        });
    out.zeroize();
    key
}

pub fn generate_device_key() -> Result<RsaPrivateKey> {
    RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|_| Error::EncryptionError("failed to generate RSA key"))
}

pub fn encrypt_private_key(
    key: &RsaPrivateKey,
    password: &[u8],
    params: KdfParams,
) -> Result<EncryptedKeyFile> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let derived = derive_key(password, &salt, params)?;
    let der = key
        .to_pkcs8_der()
        .map_err(|_| Error::EncryptionError("failed to encode private key"))?;
    let encrypted = key_store::encrypt_aes256_gcm(&derived, der.as_bytes())?;
    Ok(EncryptedKeyFile {
        version: KEY_FILE_VERSION,
        kdf: KDF_NAME.to_string(),
        m_cost_kib: params.m_cost_kib,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt_b64: BASE64.encode(salt),
        encrypted_key_b64: encrypted.unlock_slice(|b| BASE64.encode(b)),
    })
}

pub fn decrypt_private_key(file: &EncryptedKeyFile, password: &[u8]) -> Result<RsaPrivateKey> {
    if file.version != KEY_FILE_VERSION || file.kdf != KDF_NAME {
        return Err(Error::InvalidRequest(
            "unsupported local device key file version".into(),
        ));
    }
    if file.m_cost_kib > MAX_M_COST_KIB || file.t_cost > MAX_T_COST || file.p_cost > MAX_P_COST {
        return Err(Error::InvalidRequest(
            "local device key file KDF parameters out of range".into(),
        ));
    }
    let salt = BASE64
        .decode(&file.salt_b64)
        .map_err(|_| Error::InvalidRequest("invalid salt encoding".into()))?;
    let encrypted = BASE64
        .decode(&file.encrypted_key_b64)
        .map_err(|_| Error::InvalidRequest("invalid key encoding".into()))?;
    let derived = derive_key(
        password,
        &salt,
        KdfParams {
            m_cost_kib: file.m_cost_kib,
            t_cost: file.t_cost,
            p_cost: file.p_cost,
        },
    )?;
    // AES-GCM authentication failure here means a wrong password (or tampering).
    let der = key_store::decrypt_aes256_gcm(&derived, &encrypted)
        .map_err(|_| Error::EncryptionError("wrong password or corrupted key file"))?;
    der.unlock_slice(|der| RsaPrivateKey::from_pkcs8_der(der))
        .map_err(|_| Error::EncryptionError("invalid private key in key file"))
}

pub fn write_key_file(path: &Path, file: &EncryptedKeyFile) -> Result {
    let json = serde_json::to_vec_pretty(file)
        .map_err(|_| Error::EncryptionError("failed to serialize key file"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&json)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn read_key_file(path: &Path) -> Result<EncryptedKeyFile> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::InvalidRequest(format!("invalid local device key file: {e}")))
}

pub fn key_file_path(key_dir: &Path, device_uuid: &str) -> PathBuf {
    key_store::device_dir(key_dir, DeviceKind::Local, device_uuid)
        .join(key_store::LOCAL_DEVICE_PRIVATE_KEY_FILE)
}

/// Finds `(device_uuid, key file path)` for every local device key file.
pub fn find_key_files(key_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let dir = key_dir
        .join("device-keys")
        .join(DeviceKind::Local.dir_name());
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path().join(key_store::LOCAL_DEVICE_PRIVATE_KEY_FILE);
        if path.is_file() {
            found.push((entry.file_name().to_string_lossy().into_owned(), path));
        }
    }
    found.sort();
    Ok(found)
}

pub fn public_key_info(key: &RsaPrivateKey) -> Result<PublicKeyInfo> {
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|_| Error::EncryptionError("failed to encode public key"))?;
    Ok(PublicKeyInfo {
        algorithm: "RSA-OAEP-256".into(),
        format: "X.509 SubjectPublicKeyInfo".into(),
        value_b64: BASE64.encode(spki.as_bytes()),
        parameters: PublicKeyParameters {
            digest: "SHA-256".into(),
            mgf: "MGF1".into(),
            mgf_digest: "SHA-1".into(),
        },
    })
}

fn app_info() -> AppInfo {
    AppInfo {
        package_name: "alohomora-local-device".into(),
        version_name: env!("CARGO_PKG_VERSION").into(),
        version_code: 1,
    }
}

pub fn build_register_request(
    device_uuid: &Uuid,
    keychain: KeychainInfo,
    initialisation_token: &str,
    public_key: PublicKeyInfo,
) -> RegisterRequest {
    RegisterRequest {
        schema_version: 1,
        device_uuid: device_uuid.to_string(),
        keychain,
        device_name: LOCAL_DEVICE_NAME.into(),
        initialisation_token: Some(initialisation_token.to_string()),
        public_key,
        fcm: None,
        app: app_info(),
        device: DeviceInfo {
            os: LOCAL_DEVICE_OS.into(),
            sdk_int: 0,
            release: String::new(),
            manufacturer: "alohomora".into(),
            model: "local-terminal".into(),
            product: "alohomora-local-device".into(),
        },
        registered_at_ms: Timestamp::now().as_millisecond(),
    }
}

/// Values extracted from the setup URL printed by `alohomora-setup` (or a bare
/// pairing token).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SetupInfo {
    pub token: String,
    pub domain: Option<String>,
    pub port: Option<u16>,
    pub service_uuid: Option<String>,
    pub service_name: Option<String>,
}

pub fn parse_setup_input(input: &str) -> Result<SetupInfo> {
    let input = input.trim();
    let mut info = SetupInfo::default();
    match input.split_once('?') {
        None => info.token = input.to_string(),
        Some((_, query)) => {
            for pair in query.split('&') {
                let Some((k, v)) = pair.split_once('=') else {
                    continue;
                };
                match k {
                    "t" => info.token = v.to_string(),
                    "d" => info.domain = Some(v.to_string()),
                    "p" => info.port = v.parse().ok(),
                    "su" => info.service_uuid = Some(v.to_string()),
                    "sn" => info.service_name = Some(percent_decode(v)),
                    _ => {}
                }
            }
        }
    }
    key_store::parse_pairing_token(&info.token)?;
    Ok(info)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    key.decrypt(Oaep::new_with_mgf_hash::<Sha256, Sha1>(), ciphertext)
        .or_else(|_| key.decrypt(Oaep::new::<Sha256>(), ciphertext))
        .map_err(|_| Error::EncryptionError("failed to decrypt challenge"))
}

/// Decrypts a challenge with the device key, verifies it and builds the
/// response request for `POST /alohomora/authenticate`.
pub fn answer_challenge(
    key: &RsaPrivateKey,
    challenge: &LocalChallenge,
) -> Result<AuthenticateRequest> {
    let request_uuid = Uuid::parse_str(&challenge.request_uuid)
        .map_err(|_| Error::InvalidRequest("invalid request_uuid in challenge".into()))?;
    let blob = BASE64
        .decode(&challenge.encrypted_blob)
        .map_err(|_| Error::InvalidRequest("encrypted_blob is not valid base64".into()))?;
    let mut plaintext = oaep_decrypt(key, &blob)?;

    let result = (|| {
        if plaintext.len() != CHALLENGE_PLAINTEXT_LEN || &plaintext[0..5] != CHALLENGE_MAGIC {
            return Err(Error::InvalidRequest("malformed challenge".into()));
        }
        if &plaintext[5..21] != request_uuid.as_bytes() {
            return Err(Error::InvalidRequest(
                "challenge request_uuid mismatch".into(),
            ));
        }
        let ephemeral_der = BASE64
            .decode(&challenge.ephemeral_public_key)
            .map_err(|_| Error::InvalidRequest("invalid ephemeral public key".into()))?;
        if Sha256::digest(&ephemeral_der).as_slice() != &plaintext[21..53] {
            return Err(Error::InvalidRequest(
                "ephemeral public key hash mismatch; refusing to respond".into(),
            ));
        }
        let ephemeral = RsaPublicKey::from_public_key_der(&ephemeral_der)
            .map_err(|_| Error::InvalidRequest("invalid ephemeral public key".into()))?;
        let mut response = create_response_plaintext(&request_uuid, &plaintext[53..137])?;
        let encrypted = ephemeral
            .encrypt(
                &mut OsRng,
                Oaep::new_with_mgf_hash::<Sha256, Sha1>(),
                &response,
            )
            .map_err(|_| Error::EncryptionError("failed to encrypt response"));
        response.zeroize();
        encrypted
    })();
    plaintext.zeroize();
    let encrypted = result?;

    Ok(AuthenticateRequest {
        schema_version: 1,
        request_uuid: challenge.request_uuid.clone(),
        device_uuid: challenge.device_uuid.clone(),
        keychain: KeychainInfo {
            domain: challenge.domain.clone(),
            port: challenge
                .port
                .parse()
                .map_err(|_| Error::InvalidRequest("invalid port in challenge".into()))?,
            service_uuid: challenge.service_uuid.clone(),
            service_name: challenge.service_name.clone(),
        },
        decrypted_blob_b64: BASE64.encode(encrypted),
        app: app_info(),
        approved_at_ms: Timestamp::now().as_millisecond(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn key_file_round_trip_and_wrong_password() {
        let key = generate_device_key().unwrap();
        let file = encrypt_private_key(&key, b"correct horse", FAST).unwrap();
        assert_eq!(file.version, KEY_FILE_VERSION);

        let dir = std::env::temp_dir().join(format!("alhm_kf_{}", nanoid::nanoid!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.json");
        write_key_file(&path, &file).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let loaded = read_key_file(&path).unwrap();
        let restored = decrypt_private_key(&loaded, b"correct horse").unwrap();
        assert_eq!(restored, key);
        assert!(decrypt_private_key(&loaded, b"wrong").is_err());

        let mut tampered = loaded.clone();
        tampered.m_cost_kib = u32::MAX;
        assert!(decrypt_private_key(&tampered, b"correct horse").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_setup_url_and_bare_token() {
        let token = "alohomora-abcdefghij-".to_string() + &bs58::encode([7u8; 32]).into_string();
        let url = format!(
            "https://alohomora.app/register?d=example.com&p=443&t={token}&su=uuid-1&sn=My%20Host"
        );
        let info = parse_setup_input(&url).unwrap();
        assert_eq!(info.token, token);
        assert_eq!(info.domain.as_deref(), Some("example.com"));
        assert_eq!(info.port, Some(443));
        assert_eq!(info.service_name.as_deref(), Some("My Host"));
        assert_eq!(parse_setup_input(&token).unwrap().token, token);
        assert!(parse_setup_input("garbage").is_err());
    }
}

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AUTH_VERSION: u8 = 2;
const KEYRING_SERVICE: &str = "shex";
const AUTH_DIRECTORY: &str = "auth";

#[derive(Serialize, Deserialize)]
pub struct StoredAuth {
    pub redis_url: String,
    pub hostname: String,
    pub server_signature: String,
    pub code: Vec<u8>,
    pub last_session: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u8,
    key_id: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

pub struct AuthFile {
    pub data: StoredAuth,
    path: PathBuf,
    key_id: String,
}

impl AuthFile {
    pub fn create_for_host(data: StoredAuth, store_dir: &Path) -> Result<Self> {
        ensure_private_directory(store_dir)?;
        let auth_dir = store_dir.join(AUTH_DIRECTORY);
        ensure_private_directory(&auth_dir)?;
        let path = host_path(store_dir, &data.hostname);

        if path.exists() {
            let mut existing = Self::load(&path)?;
            let mut data = data;
            if existing.data.server_signature == data.server_signature
                && existing.data.redis_url == data.redis_url
            {
                data.last_session = existing.data.last_session.clone();
            }
            existing.data = data;
            existing.save()?;
            return Ok(existing);
        }

        let key_id = random_hex::<16>();
        let key: [u8; 32] = rand::random();
        keyring_entry(store_dir, &key_id)?
            .set_secret(&key)
            .context("could not store the auth encryption key in secure credential storage")?;

        let auth = Self { data, path, key_id };
        if let Err(error) = auth.write_new(&key) {
            let _ =
                keyring_entry(store_dir, &auth.key_id).and_then(|entry| entry.delete_credential());
            return Err(error);
        }
        Ok(auth)
    }

    pub fn load_for_host(store_dir: &Path, hostname: &str) -> Result<Self> {
        let path = host_path(store_dir, hostname);
        Self::load(&path).with_context(|| {
            format!("no saved authentication for `{hostname}`; run `shex auth {hostname}` first")
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        check_private_permissions(path)?;
        let bytes = fs::read(path)
            .with_context(|| format!("could not read auth file {}", path.display()))?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).context("invalid shex auth file")?;
        if envelope.version != AUTH_VERSION {
            bail!("unsupported shex auth file version {}", envelope.version);
        }
        let store_dir = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("auth file has no store directory"))?;
        let key = keyring_entry(store_dir, &envelope.key_id)?
            .get_secret()
            .context("could not retrieve this auth file's key from secure credential storage")?;
        let data = decrypt(&envelope, &key)?;
        Ok(Self {
            data,
            path: path.to_owned(),
            key_id: envelope.key_id,
        })
    }

    pub fn save(&self) -> Result<()> {
        let store_dir = self
            .path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("auth file has no store directory"))?;
        let key = keyring_entry(store_dir, &self.key_id)?
            .get_secret()
            .context("could not retrieve this auth file's key from secure credential storage")?;
        let bytes = encrypt(&self.data, &self.key_id, &key)?;
        write_private_replace(&self.path, &bytes)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_new(&self, key: &[u8]) -> Result<()> {
        let bytes = encrypt(&self.data, &self.key_id, key)?;
        write_private_new(&self.path, &bytes)
    }
}

pub fn default_store_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".shex")
}

fn host_path(store_dir: &Path, hostname: &str) -> PathBuf {
    let digest = Sha256::digest(hostname.as_bytes());
    let name: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    store_dir.join(AUTH_DIRECTORY).join(format!("{name}.auth"))
}

fn keyring_entry(store_dir: &Path, key_id: &str) -> Result<crate::credential_store::Entry> {
    crate::credential_store::entry(store_dir, KEYRING_SERVICE, key_id)
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path).with_context(|| format!("could not create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("could not secure {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("could not create {}", path.display()))?;
    Ok(())
}

fn encrypt(data: &StoredAuth, key_id: &str, key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("auth encryption key has an invalid length");
    }
    let nonce: [u8; 12] = rand::random();
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid auth encryption key"))?;
    let plaintext = serde_json::to_vec(data)?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: key_id.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("could not encrypt auth file"))?;
    Ok(serde_json::to_vec(&Envelope {
        version: AUTH_VERSION,
        key_id: key_id.to_owned(),
        nonce,
        ciphertext,
    })?)
}

fn decrypt(envelope: &Envelope, key: &[u8]) -> Result<StoredAuth> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid auth encryption key"))?;
    let plaintext = cipher
        .decrypt(
            (&envelope.nonce).into(),
            Payload {
                msg: &envelope.ciphertext,
                aad: envelope.key_id.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("auth file authentication failed"))?;
    serde_json::from_slice(&plaintext).context("invalid decrypted auth data")
}

fn random_hex<const N: usize>() -> String {
    let bytes: [u8; N] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "auth file {} is not private; run `chmod 600 {}`",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(unix)]
fn write_private_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Envelope, StoredAuth, decrypt, encrypt, host_path};
    use std::path::Path;

    #[test]
    fn auth_payload_is_encrypted_and_authenticated() {
        let key = [7u8; 32];
        let data = StoredAuth {
            redis_url: "redis://127.0.0.1/".into(),
            hostname: "quiet-fox:1738".into(),
            server_signature: "server-a".into(),
            code: b"secret-code".to_vec(),
            last_session: Some("session-a".into()),
        };
        let bytes = encrypt(&data, "key-a", &key).unwrap();
        assert!(!bytes.windows(data.code.len()).any(|part| part == data.code));

        let envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        let restored = decrypt(&envelope, &key).unwrap();
        assert_eq!(restored.code, data.code);
        assert_eq!(restored.last_session, data.last_session);
        assert!(decrypt(&envelope, &[8u8; 32]).is_err());
    }

    #[test]
    fn host_auth_paths_are_deterministic_and_do_not_expose_hostnames() {
        let first = host_path(Path::new("/tmp/store"), "quiet-fox:1738");
        let second = host_path(Path::new("/tmp/store"), "quiet-fox:1738");
        assert_eq!(first, second);
        assert!(!first.to_string_lossy().contains("quiet-fox"));
        assert_eq!(
            first.extension().and_then(|value| value.to_str()),
            Some("auth")
        );
    }
}

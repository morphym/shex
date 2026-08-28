use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use keyring::v1::Entry;
use serde::{Deserialize, Serialize};

const AUTH_VERSION: u8 = 1;
const KEYRING_SERVICE: &str = "shex";
const DEFAULT_AUTH_FILE: &str = ".shex_auth";

#[derive(Serialize, Deserialize)]
pub struct StoredAuth {
    pub address: SocketAddr,
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
    pub fn create(data: StoredAuth) -> Result<Self> {
        let path = available_path();
        let key_id = random_hex::<16>();
        let key: [u8; 32] = rand::random();
        keyring_entry(&key_id)?
            .set_secret(&key)
            .context("could not store the auth encryption key in the OS credential store")?;

        let auth = Self { data, path, key_id };
        if let Err(error) = auth.write_new(&key) {
            let _ = keyring_entry(&auth.key_id)
                .and_then(|entry| entry.delete_credential().map_err(Into::into));
            return Err(error);
        }
        Ok(auth)
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
        let key = keyring_entry(&envelope.key_id)?
            .get_secret()
            .context("could not retrieve this auth file's key from the OS credential store")?;
        let data = decrypt(&envelope, &key)?;
        Ok(Self {
            data,
            path: path.to_owned(),
            key_id: envelope.key_id,
        })
    }

    pub fn save(&self) -> Result<()> {
        let key = keyring_entry(&self.key_id)?
            .get_secret()
            .context("could not retrieve this auth file's key from the OS credential store")?;
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

fn available_path() -> PathBuf {
    let default = PathBuf::from(DEFAULT_AUTH_FILE);
    if !default.exists() {
        return default;
    }
    for index in 1u32.. {
        let candidate = PathBuf::from(format!("{DEFAULT_AUTH_FILE}_{index:02}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

fn keyring_entry(key_id: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, key_id).context("OS credential store is unavailable")
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
    use super::{Envelope, StoredAuth, decrypt, encrypt};

    #[test]
    fn auth_payload_is_encrypted_and_authenticated() {
        let key = [7u8; 32];
        let data = StoredAuth {
            address: "127.0.0.1:8022".parse().unwrap(),
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
}

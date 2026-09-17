use std::{path::Path, sync::LazyLock};

#[cfg(target_os = "linux")]
use std::{fs, io::Write, path::PathBuf};

#[cfg(target_os = "linux")]
use anyhow::bail;
use anyhow::{Context, Result, anyhow};
#[cfg(target_os = "linux")]
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use keyring_core::Entry as SystemEntry;
#[cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
const FILE_STORE_VERSION: u8 = 1;
#[cfg(target_os = "linux")]
const FILE_STORE_DIRECTORY: &str = "credentials";
#[cfg(target_os = "linux")]
const FILE_STORE_KEY: &str = "credential.key";

#[derive(Clone, Copy)]
enum Backend {
    System,
    #[cfg(target_os = "linux")]
    LinuxKernel,
    #[cfg(target_os = "linux")]
    EncryptedFile,
}

static BACKEND: LazyLock<std::result::Result<Backend, String>> = LazyLock::new(configure_backend);

pub enum Entry {
    System(SystemEntry),
    #[cfg(target_os = "linux")]
    EncryptedFile(FileEntry),
}

impl Entry {
    pub fn set_secret(&self, secret: &[u8]) -> Result<()> {
        match self {
            Self::System(entry) => entry
                .set_secret(secret)
                .context("could not write to the OS credential store"),
            #[cfg(target_os = "linux")]
            Self::EncryptedFile(entry) => entry.set_secret(secret),
        }
    }

    pub fn get_secret(&self) -> Result<Vec<u8>> {
        match self {
            Self::System(entry) => entry
                .get_secret()
                .context("could not read from the OS credential store"),
            #[cfg(target_os = "linux")]
            Self::EncryptedFile(entry) => entry.get_secret(),
        }
    }

    pub fn delete_credential(&self) -> Result<()> {
        match self {
            Self::System(entry) => entry
                .delete_credential()
                .context("could not delete from the OS credential store"),
            #[cfg(target_os = "linux")]
            Self::EncryptedFile(entry) => entry.delete_credential(),
        }
    }
}

pub fn entry(store_dir: &Path, service: &str, user: &str) -> Result<Entry> {
    #[cfg(not(target_os = "linux"))]
    let _ = store_dir;
    let backend = *BACKEND
        .as_ref()
        .map_err(|message| anyhow!("secure credential storage is unavailable: {message}"))?;
    match backend {
        Backend::System => SystemEntry::new(service, user)
            .map(Entry::System)
            .context("OS credential store is unavailable"),
        #[cfg(target_os = "linux")]
        Backend::LinuxKernel => SystemEntry::new(service, user)
            .map(Entry::System)
            .context("Linux kernel credential store is unavailable"),
        #[cfg(target_os = "linux")]
        Backend::EncryptedFile => Ok(Entry::EncryptedFile(FileEntry::new(
            store_dir, service, user,
        ))),
    }
}

pub fn fallback_notice() -> Option<&'static str> {
    match BACKEND.as_ref() {
        #[cfg(target_os = "linux")]
        Ok(Backend::LinuxKernel) => Some(
            "credential store: Linux kernel keyring (secure and memory-backed; re-add credentials after reboot)",
        ),
        #[cfg(target_os = "linux")]
        Ok(Backend::EncryptedFile) => Some(
            "credential store: encrypted local shex vault protected by private OS file permissions",
        ),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn configure_backend() -> std::result::Result<Backend, String> {
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|error| format!("could not open macOS Keychain: {error}"))?;
    keyring_core::set_default_store(store);
    Ok(Backend::System)
}

#[cfg(target_os = "windows")]
fn configure_backend() -> std::result::Result<Backend, String> {
    let store = windows_native_keyring_store::Store::new()
        .map_err(|error| format!("could not open Windows Credential Manager: {error}"))?;
    keyring_core::set_default_store(store);
    Ok(Backend::System)
}

#[cfg(target_os = "linux")]
fn configure_backend() -> std::result::Result<Backend, String> {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        if let Ok(store) = zbus_secret_service_keyring_store::Store::new() {
            keyring_core::set_default_store(store);
            if probe_current_store().is_ok() {
                return Ok(Backend::System);
            }
        }
    }

    if let Ok(store) = linux_keyutils_keyring_store::Store::new() {
        keyring_core::set_default_store(store);
        if probe_current_store().is_ok() {
            return Ok(Backend::LinuxKernel);
        }
    }

    Ok(Backend::EncryptedFile)
}

#[cfg(target_os = "linux")]
fn probe_current_store() -> std::result::Result<(), String> {
    let user = format!("probe-{:032x}", rand::random::<u128>());
    let entry = SystemEntry::new("shex-probe", &user).map_err(|error| error.to_string())?;
    let secret: [u8; 32] = rand::random();
    entry
        .set_secret(&secret)
        .map_err(|error| error.to_string())?;
    let result = entry
        .get_secret()
        .map_err(|error| error.to_string())
        .and_then(|stored| {
            if stored == secret {
                Ok(())
            } else {
                Err("credential probe returned different bytes".to_owned())
            }
        });
    let _ = entry.delete_credential();
    result
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn configure_backend() -> std::result::Result<Backend, String> {
    Err("this operating system has no configured shex credential backend".to_owned())
}

#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
struct FileEnvelope {
    version: u8,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[cfg(target_os = "linux")]
pub struct FileEntry {
    store_dir: PathBuf,
    path: PathBuf,
    aad: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl FileEntry {
    fn new(store_dir: &Path, service: &str, user: &str) -> Self {
        let mut identity = service.as_bytes().to_vec();
        identity.push(0);
        identity.extend_from_slice(user.as_bytes());
        let name = hex_digest(&identity);
        Self {
            store_dir: store_dir.to_owned(),
            path: store_dir
                .join(FILE_STORE_DIRECTORY)
                .join(format!("{name}.secret")),
            aad: identity,
        }
    }

    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let key = load_or_create_file_key(&self.store_dir)?;
        let nonce: [u8; 12] = rand::random();
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid local credential-store key"))?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: secret,
                    aad: &self.aad,
                },
            )
            .map_err(|_| anyhow!("could not encrypt the local credential"))?;
        let bytes = serde_json::to_vec(&FileEnvelope {
            version: FILE_STORE_VERSION,
            nonce,
            ciphertext,
        })?;
        write_private_replace(&self.path, &bytes)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        let key = load_file_key(&self.store_dir)?;
        check_private_permissions(&self.path)?;
        let envelope: FileEnvelope = serde_json::from_slice(
            &fs::read(&self.path)
                .with_context(|| format!("could not read credential {}", self.path.display()))?,
        )
        .context("invalid encrypted credential")?;
        if envelope.version != FILE_STORE_VERSION {
            bail!("unsupported encrypted credential version");
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid local credential-store key"))?;
        cipher
            .decrypt(
                (&envelope.nonce).into(),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| anyhow!("local credential authentication failed"))
    }

    fn delete_credential(&self) -> Result<()> {
        fs::remove_file(&self.path)
            .with_context(|| format!("could not delete credential {}", self.path.display()))
    }
}

#[cfg(target_os = "linux")]
fn load_or_create_file_key(store_dir: &Path) -> Result<[u8; 32]> {
    use std::os::unix::fs::OpenOptionsExt;

    ensure_private_directory(store_dir)?;
    ensure_private_directory(&store_dir.join(FILE_STORE_DIRECTORY))?;
    let path = store_dir.join(FILE_STORE_KEY);
    if path.exists() {
        return load_file_key(store_dir);
    }

    let key: [u8; 32] = rand::random();
    let temp = store_dir.join(format!(
        ".credential-key-{:032x}.tmp",
        rand::random::<u128>()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("could not create {}", temp.display()))?;
    file.write_all(&key)?;
    file.sync_all()?;
    drop(file);

    let result = match fs::hard_link(&temp, &path) {
        Ok(()) => Ok(key),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => load_file_key(store_dir),
        Err(error) => Err(error).with_context(|| format!("could not create {}", path.display())),
    };
    let _ = fs::remove_file(temp);
    result
}

#[cfg(target_os = "linux")]
fn load_file_key(store_dir: &Path) -> Result<[u8; 32]> {
    let path = store_dir.join(FILE_STORE_KEY);
    check_private_permissions(&path)?;
    let bytes = fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("local credential-store key has an invalid length"))
}

#[cfg(target_os = "linux")]
fn ensure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path).with_context(|| format!("could not create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("could not secure {}", path.display()))
}

#[cfg(target_os = "linux")]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "credential file {} is not private; run `chmod 600 {}`",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_private_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("credential path has no parent"))?;
    ensure_private_directory(parent)?;
    let temp = parent.join(format!(".credential-{:032x}.tmp", rand::random::<u128>()));
    let result: Result<()> = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.with_context(|| format!("could not write credential {}", path.display()))
}

#[cfg(target_os = "linux")]
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{FileEntry, entry};

    #[test]
    fn headless_linux_store_round_trips_a_secret() {
        let root = std::env::temp_dir().join(format!("shex-store-{:032x}", rand::random::<u128>()));
        let user = format!("test-{:016x}", rand::random::<u64>());
        let entry = entry(&root, "shex-test", &user).expect("credential store should initialize");
        entry
            .set_secret(b"not-a-real-credential")
            .expect("secret should be stored");
        assert_eq!(
            entry.get_secret().expect("secret should be retrieved"),
            b"not-a-real-credential"
        );
        entry
            .delete_credential()
            .expect("test credential should be deleted");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn encrypted_file_store_never_writes_plaintext() {
        let root = std::env::temp_dir().join(format!("shex-vault-{:032x}", rand::random::<u128>()));
        let secret = b"redis://user:password@example.invalid/";
        let entry = FileEntry::new(&root, "shex-test", "local");
        entry.set_secret(secret).unwrap();

        let bytes = std::fs::read(&entry.path).unwrap();
        assert!(!bytes.windows(secret.len()).any(|part| part == secret));
        assert_eq!(
            std::fs::metadata(&entry.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(entry.get_secret().unwrap(), secret);

        let _ = std::fs::remove_dir_all(root);
    }
}

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use keyring::v1::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const STORE_VERSION: u8 = 1;
const KEYRING_SERVICE: &str = "shex-redis";

#[derive(Serialize, Deserialize)]
struct Marker {
    version: u8,
    name: String,
}

pub fn add(store_dir: &Path, name: &str, redis_url: &str) -> Result<PathBuf> {
    validate_name(name)?;
    redis::Client::open(redis_url).context("invalid Redis URL")?;
    let directory = store_dir.join("redis");
    ensure_private_directory(store_dir)?;
    ensure_private_directory(&directory)?;

    keyring_entry(name)?
        .set_secret(redis_url.as_bytes())
        .context("could not store the Redis URL in the OS credential store")?;
    let path = marker_path(store_dir, name);
    let marker = serde_json::to_vec(&Marker {
        version: STORE_VERSION,
        name: name.to_owned(),
    })?;
    write_private(&path, &marker)?;
    Ok(path)
}

pub fn resolve(store_dir: &Path, reference: &str) -> Result<String> {
    if reference.contains("://") {
        redis::Client::open(reference).context("invalid Redis URL")?;
        return Ok(reference.to_owned());
    }
    validate_name(reference)?;
    let path = marker_path(store_dir, reference);
    check_private_permissions(&path)?;
    let marker: Marker = serde_json::from_slice(&fs::read(&path).with_context(|| {
        format!("unknown Redis server `{reference}`; add it with `shex redis add {reference} URL`")
    })?)
    .context("invalid local Redis server marker")?;
    if marker.version != STORE_VERSION || marker.name != reference {
        bail!("local Redis server marker does not match `{reference}`");
    }
    let secret = keyring_entry(reference)?
        .get_secret()
        .context("could not retrieve the Redis URL from the OS credential store")?;
    let redis_url = String::from_utf8(secret).context("stored Redis URL is not valid UTF-8")?;
    redis::Client::open(redis_url.as_str()).context("stored Redis URL is invalid")?;
    Ok(redis_url)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("Redis server name must be 1-63 letters, digits, hyphens, or underscores");
    }
    Ok(())
}

fn server_hash(name: &str) -> String {
    Sha256::digest(name.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn marker_path(store_dir: &Path, name: &str) -> PathBuf {
    store_dir
        .join("redis")
        .join(format!("{}.server", server_hash(name)))
}

fn keyring_entry(name: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, &server_hash(name)).context("OS credential store is unavailable")
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

#[cfg(unix)]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        bail!("Redis server marker {} is not private", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{marker_path, validate_name};
    use std::path::Path;

    #[test]
    fn validates_local_server_names() {
        assert!(validate_name("local_redis-1").is_ok());
        assert!(validate_name("bad/name").is_err());
        assert!(validate_name("").is_err());
    }

    #[test]
    fn marker_paths_do_not_expose_names() {
        let path = marker_path(Path::new("/tmp/store"), "production");
        assert!(!path.to_string_lossy().contains("production"));
        assert_eq!(
            path.extension().and_then(|value| value.to_str()),
            Some("server")
        );
    }
}

use std::{
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

use crate::channel::FrameTransport;

const MESSAGE_TTL_MS: u64 = 60_000;
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(65);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const LEASE_INTERVAL: Duration = Duration::from_secs(20);
const SEND_SCRIPT: &str = r#"
if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then
    redis.call('RPUSH', KEYS[2], '1')
    redis.call('PEXPIRE', KEYS[2], ARGV[2])
    return 1
end
return 0
"#;
const ACK_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"#;
const RENEW_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
"#;

pub struct LatencyStats {
    pub minimum: Duration,
    pub average: Duration,
    pub maximum: Duration,
}

pub fn measure_latency(redis_url: &str, count: u32) -> Result<LatencyStats> {
    if count == 0 {
        bail!("latency sample count must be at least one");
    }
    let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
    let mut connection = client
        .get_connection()
        .context("could not connect to Redis")?;
    let pong: String = redis::cmd("PING")
        .query(&mut connection)
        .context("Redis latency warm-up failed")?;
    if pong != "PONG" {
        bail!("Redis returned an invalid PING response");
    }

    let mut samples = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let started = Instant::now();
        let pong: String = redis::cmd("PING")
            .query(&mut connection)
            .context("Redis latency test failed")?;
        if pong != "PONG" {
            bail!("Redis returned an invalid PING response");
        }
        samples.push(started.elapsed());
    }
    let minimum = *samples.iter().min().expect("latency samples are non-empty");
    let maximum = *samples.iter().max().expect("latency samples are non-empty");
    let total: Duration = samples.iter().copied().sum();
    Ok(LatencyStats {
        minimum,
        average: total / count,
        maximum,
    })
}

struct PendingMessage {
    value: Vec<u8>,
    stop_lease: Sender<()>,
}

pub struct RedisTransport {
    redis_url: String,
    connection: redis::Connection,
    send_key: String,
    recv_key: String,
    send_ready_key: String,
    recv_ready_key: String,
    wake_queue: Option<String>,
    pending: Option<PendingMessage>,
    receive_timeout_seconds: u64,
}

impl RedisTransport {
    pub fn client(redis_url: &str, hostname: &str) -> Result<Self> {
        validate_hostname(hostname)?;
        let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
        let mut connection = client
            .get_connection()
            .context("could not connect to Redis")?;
        let exists: bool = redis::cmd("EXISTS")
            .arg(host_key(hostname))
            .query(&mut connection)
            .context("could not look up shex host in Redis")?;
        if !exists {
            bail!("unknown shex hostname `{hostname}`");
        }
        let connection_id = random_hex::<16>();
        let send_key = client_message_key(hostname, &connection_id);
        let recv_key = host_message_key(hostname, &connection_id);
        Ok(Self {
            redis_url: redis_url.to_owned(),
            connection,
            send_ready_key: ready_key(&send_key),
            recv_ready_key: ready_key(&recv_key),
            send_key,
            recv_key,
            wake_queue: Some(wake_key(hostname)),
            pending: None,
            receive_timeout_seconds: MESSAGE_TIMEOUT.as_secs(),
        })
    }

    fn server(redis_url: &str, hostname: &str, connection_id: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
        let connection = client
            .get_connection()
            .context("could not connect to Redis")?;
        let send_key = host_message_key(hostname, connection_id);
        let recv_key = client_message_key(hostname, connection_id);
        Ok(Self {
            redis_url: redis_url.to_owned(),
            connection,
            send_ready_key: ready_key(&send_key),
            recv_ready_key: ready_key(&recv_key),
            send_key,
            recv_key,
            wake_queue: None,
            pending: None,
            receive_timeout_seconds: MESSAGE_TIMEOUT.as_secs(),
        })
    }

    fn notify_host(&mut self) -> Result<()> {
        let Some(queue) = self.wake_queue.take() else {
            return Ok(());
        };
        let connection_id = self
            .send_key
            .rsplit(':')
            .next()
            .context("invalid Redis connection key")?;
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("RPUSH")
            .arg(&queue)
            .arg(connection_id)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&queue)
            .arg(MESSAGE_TTL_MS)
            .ignore();
        pipe.query::<()>(&mut self.connection)
            .context("could not notify the shex host")
    }
}

impl FrameTransport for RedisTransport {
    fn send_frame(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > 16 * 1024 * 1024 {
            bail!("Redis message exceeds 16 MiB");
        }
        let deadline = Instant::now() + MESSAGE_TIMEOUT;
        loop {
            let stored: i64 = redis::cmd("EVAL")
                .arg(SEND_SCRIPT)
                .arg(2)
                .arg(&self.send_key)
                .arg(&self.send_ready_key)
                .arg(data)
                .arg(MESSAGE_TTL_MS)
                .query(&mut self.connection)
                .context("could not write encrypted Redis message")?;
            if stored == 1 {
                self.notify_host()?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("previous Redis message was not acknowledged");
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        if self.pending.is_some() {
            bail!("received Redis message has not been acknowledged");
        }
        let ready: Option<(String, String)> = redis::cmd("BLPOP")
            .arg(&self.recv_ready_key)
            .arg(self.receive_timeout_seconds)
            .query(&mut self.connection)
            .context("could not wait for an encrypted Redis message")?;
        ready.context("timed out waiting for an encrypted Redis message")?;

        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&self.recv_key)
            .query(&mut self.connection)
            .context("could not read encrypted Redis message")?;
        let value = value.context("encrypted Redis message expired before it was received")?;
        let stop_lease =
            start_processing_lease(self.redis_url.clone(), self.recv_key.clone(), value.clone());
        self.pending = Some(PendingMessage {
            value: value.clone(),
            stop_lease,
        });
        Ok(value)
    }

    fn acknowledge(&mut self) -> Result<()> {
        let pending = self
            .pending
            .take()
            .context("no Redis message to acknowledge")?;
        let _ = pending.stop_lease.send(());
        let removed: i64 = redis::cmd("EVAL")
            .arg(ACK_SCRIPT)
            .arg(1)
            .arg(&self.recv_key)
            .arg(pending.value)
            .query(&mut self.connection)
            .context("could not acknowledge encrypted Redis message")?;
        if removed != 1 {
            bail!("Redis message changed or expired before acknowledgement");
        }
        Ok(())
    }

    fn wait_indefinitely(&mut self) {
        self.receive_timeout_seconds = 0;
    }
}

fn start_processing_lease(redis_url: String, key: String, value: Vec<u8>) -> Sender<()> {
    let (stop, stopped) = mpsc::channel();
    thread::spawn(move || {
        let Ok(client) = redis::Client::open(redis_url) else {
            return;
        };
        let Ok(mut connection) = client.get_connection() else {
            return;
        };
        loop {
            match stopped.recv_timeout(LEASE_INTERVAL) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {}
            }
            let renewed: redis::RedisResult<i64> = redis::cmd("EVAL")
                .arg(RENEW_SCRIPT)
                .arg(1)
                .arg(&key)
                .arg(&value)
                .arg(MESSAGE_TTL_MS)
                .query(&mut connection);
            if !matches!(renewed, Ok(1)) {
                return;
            }
        }
    });
    stop
}

pub struct HostListener {
    redis_url: String,
    hostname: String,
    connection: redis::Connection,
}

impl HostListener {
    pub fn register(redis_url: &str, hostname: &str, signature: &str) -> Result<Self> {
        validate_hostname(hostname)?;
        let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
        let mut connection = client
            .get_connection()
            .context("could not connect to Redis")?;
        let key = host_key(hostname);
        let created: bool = redis::cmd("SETNX")
            .arg(&key)
            .arg(signature)
            .query(&mut connection)
            .context("could not register shex hostname")?;
        if !created {
            let existing: String = redis::cmd("GET")
                .arg(&key)
                .query(&mut connection)
                .context("could not read shex hostname registration")?;
            if existing != signature {
                bail!("shex hostname `{hostname}` is already owned by another host");
            }
        }
        Ok(Self {
            redis_url: redis_url.to_owned(),
            hostname: hostname.to_owned(),
            connection,
        })
    }

    pub fn accept(&mut self) -> Result<RedisTransport> {
        let result: Option<(String, String)> = redis::cmd("BLPOP")
            .arg(wake_key(&self.hostname))
            .arg(0)
            .query(&mut self.connection)
            .context("could not wait for Redis client")?;
        let (_, connection_id) = result.context("Redis listener ended unexpectedly")?;
        RedisTransport::server(&self.redis_url, &self.hostname, &connection_id)
    }
}

pub fn create_session_lookup(redis_url: &str, hostname: &str, session_id: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let session_hash: String = Sha256::digest(session_id.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
    let mut connection = client
        .get_connection()
        .context("could not connect to Redis")?;
    let key = session_key(hostname, &session_hash);
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(hostname)
        .query(&mut connection)
        .context("could not create Redis session lookup")?;
    Ok(key)
}

pub fn clear_session_lookups(redis_url: &str, hostname: &str) -> Result<()> {
    let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
    let mut connection = client
        .get_connection()
        .context("could not connect to Redis")?;
    let pattern = format!("shex:v2:{hostname}:session:*");
    let mut cursor = 0u64;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100)
            .query(&mut connection)
            .context("could not scan stale Redis session lookups")?;
        if !keys.is_empty() {
            redis::cmd("DEL")
                .arg(keys)
                .query::<i64>(&mut connection)
                .context("could not delete stale Redis session lookups")?;
        }
        cursor = next;
        if cursor == 0 {
            return Ok(());
        }
    }
}

pub fn delete_session_lookup(redis_url: &str, key: &str) -> Result<()> {
    let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
    let mut connection = client
        .get_connection()
        .context("could not connect to Redis")?;
    redis::cmd("DEL")
        .arg(key)
        .query::<i64>(&mut connection)
        .context("could not delete Redis session lookup")?;
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty()
        || hostname.len() > 63
        || !hostname.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b':')
        })
    {
        bail!("hostname must be 1-63 lowercase letters, digits, hyphens, or colons");
    }
    Ok(())
}

pub fn random_hostname() -> String {
    const LEFT: &[&str] = &[
        "quiet", "swift", "bright", "calm", "wild", "small", "blue", "green",
    ];
    const RIGHT: &[&str] = &[
        "otter", "falcon", "cedar", "river", "lynx", "cloud", "fox", "panda",
    ];
    let bytes: [u8; 4] = rand::random();
    format!(
        "{}-{}:{:04}",
        LEFT[bytes[0] as usize % LEFT.len()],
        RIGHT[bytes[1] as usize % RIGHT.len()],
        u16::from_be_bytes([bytes[2], bytes[3]]) % 10_000
    )
}

fn host_key(hostname: &str) -> String {
    format!("shex:v2:host:{hostname}")
}

fn wake_key(hostname: &str) -> String {
    format!("shex:v2:{hostname}:wake")
}

fn client_message_key(hostname: &str, connection_id: &str) -> String {
    format!("shex:v2:{hostname}:message:c2h:{connection_id}")
}

fn host_message_key(hostname: &str, connection_id: &str) -> String {
    format!("shex:v2:{hostname}:message:h2c:{connection_id}")
}

fn ready_key(message_key: &str) -> String {
    format!("{message_key}:ready")
}

fn session_key(hostname: &str, session_hash: &str) -> String {
    format!("shex:v2:{hostname}:session:{session_hash}")
}

fn random_hex<const N: usize>() -> String {
    let bytes: [u8; N] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{client_message_key, host_key, random_hostname, session_key, validate_hostname};

    #[test]
    fn generated_hostnames_are_valid() {
        for _ in 0..100 {
            let hostname = random_hostname();
            validate_hostname(&hostname).unwrap();
            assert!(hostname.contains(':'));
        }
    }

    #[test]
    fn keys_are_namespaced_by_hostname() {
        assert_eq!(host_key("quiet-fox:1738"), "shex:v2:host:quiet-fox:1738");
        assert!(client_message_key("quiet-fox:1738", "abc").contains(":message:c2h:abc"));
        assert!(session_key("quiet-fox:1738", "hash").ends_with(":session:hash"));
    }
}

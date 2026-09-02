use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Context, Result, bail};

use crate::{
    auth::{self, ServerCredentials},
    channel::SecureChannel,
    protocol::{ClientRequest, ServerReply},
    redis_transport::{self, HostListener, RedisTransport},
};

type Sessions = Arc<Mutex<HashMap<String, Arc<Session>>>>;

struct Session {
    shell: Mutex<ShellSession>,
    lookup_key: Option<String>,
}

pub fn serve(redis_url: &str, requested_hostname: Option<&str>, data_dir: &Path) -> Result<()> {
    let credentials = Arc::new(ServerCredentials::load(data_dir)?);
    let hostname = resolve_hostname(data_dir, requested_hostname)?;
    let mut listener = HostListener::register(redis_url, &hostname, credentials.signature())?;
    persist_hostname(data_dir, &hostname)?;
    redis_transport::clear_session_lookups(redis_url, &hostname)?;
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    eprintln!("shex host: {hostname}");
    eprintln!("waiting through Redis");

    loop {
        match listener.accept() {
            Ok(transport) => {
                let credentials = credentials.clone();
                let sessions = sessions.clone();
                let redis_url = redis_url.to_owned();
                let hostname = hostname.clone();
                thread::spawn(move || {
                    if let Err(error) =
                        handle(transport, &credentials, &sessions, &redis_url, &hostname)
                    {
                        eprintln!("connection ended: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("Redis accept failed: {error:#}"),
        }
    }
}

fn handle(
    mut transport: RedisTransport,
    credentials: &ServerCredentials,
    sessions: &Sessions,
    redis_url: &str,
    hostname: &str,
) -> Result<()> {
    let key = auth::server_login(&mut transport, credentials).context("authentication failed")?;
    let mut channel = SecureChannel::server(Box::new(transport), &key)?;
    channel.send(&ServerReply::Hello {
        server_signature: credentials.signature().to_owned(),
    })?;

    let (requested, persistent) = loop {
        match channel.recv_unacknowledged::<ClientRequest>()? {
            ClientRequest::Open {
                session,
                persistent,
            } => break (session, persistent),
            ClientRequest::Ping => {
                channel.acknowledge()?;
                channel.send(&ServerReply::Pong)?;
            }
            ClientRequest::DeleteSession { session } => {
                let removed = sessions.lock().unwrap().remove(&session);
                let Some(removed) = removed else {
                    channel.acknowledge()?;
                    channel.send(&ServerReply::Error {
                        message: "unknown session".into(),
                    })?;
                    return Ok(());
                };
                if let Some(key) = &removed.lookup_key {
                    redis_transport::delete_session_lookup(redis_url, key)?;
                }
                channel.acknowledge()?;
                channel.send(&ServerReply::Deleted { session })?;
                return Ok(());
            }
            ClientRequest::Disconnect => {
                channel.acknowledge()?;
                return Ok(());
            }
            ClientRequest::Run { .. } => bail!("the first request must open or delete a session"),
        }
    };

    let (id, session) = match requested {
        Some(id) => {
            let session = sessions.lock().unwrap().get(&id).cloned();
            match session {
                Some(session) => (id, session),
                None => {
                    channel.acknowledge()?;
                    channel.send(&ServerReply::Error {
                        message: "unknown session".into(),
                    })?;
                    return Ok(());
                }
            }
        }
        None => {
            let id = random_id();
            let lookup_key = if persistent {
                Some(redis_transport::create_session_lookup(
                    redis_url, hostname, &id,
                )?)
            } else {
                None
            };
            let session = Arc::new(Session {
                shell: Mutex::new(ShellSession::spawn()?),
                lookup_key,
            });
            if persistent {
                sessions.lock().unwrap().insert(id.clone(), session.clone());
            }
            (id, session)
        }
    };
    channel.acknowledge()?;
    channel.send(&ServerReply::Opened { session: id })?;
    channel.wait_indefinitely();

    loop {
        match channel.recv_unacknowledged::<ClientRequest>() {
            Ok(ClientRequest::Run { command }) => {
                let result = session.shell.lock().unwrap().run(&command);
                channel.acknowledge()?;
                match result {
                    Ok((data, status)) => channel.send(&ServerReply::Output { data, status })?,
                    Err(error) => channel.send(&ServerReply::Error {
                        message: format!("{error:#}"),
                    })?,
                }
            }
            Ok(ClientRequest::Open { .. }) => {
                channel.acknowledge()?;
                channel.send(&ServerReply::Error {
                    message: "session is already open".into(),
                })?;
            }
            Ok(ClientRequest::DeleteSession { .. }) => {
                channel.acknowledge()?;
                channel.send(&ServerReply::Error {
                    message: "cannot delete a session from an open connection".into(),
                })?;
            }
            Ok(ClientRequest::Ping) => {
                channel.acknowledge()?;
                channel.send(&ServerReply::Pong)?;
            }
            Ok(ClientRequest::Disconnect) => {
                channel.acknowledge()?;
                return Ok(());
            }
            Err(error) if is_disconnect(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn resolve_hostname(data_dir: &Path, requested: Option<&str>) -> Result<String> {
    let path = data_dir.join("hostname");
    if let Some(hostname) = requested {
        return Ok(hostname.to_owned());
    }
    if let Ok(hostname) = fs::read_to_string(&path) {
        let hostname = hostname.trim().to_owned();
        if !hostname.is_empty() {
            return Ok(hostname);
        }
    }
    Ok(redis_transport::random_hostname())
}

fn persist_hostname(data_dir: &Path, hostname: &str) -> Result<()> {
    fs::write(data_dir.join("hostname"), format!("{hostname}\n"))?;
    Ok(())
}

fn is_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            )
        })
    })
}

fn random_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct ShellSession {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl ShellSession {
    fn spawn() -> Result<Self> {
        let mut child = Command::new("sh")
            .args(["-c", "exec 2>&1; exec sh"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("could not start /bin/sh")?;
        let input = child.stdin.take().context("shell stdin unavailable")?;
        let output = BufReader::new(child.stdout.take().context("shell stdout unavailable")?);
        Ok(Self {
            child,
            input,
            output,
        })
    }

    fn run(&mut self, command: &str) -> Result<(String, i32)> {
        let marker = format!("SHEX-{}", random_id());
        writeln!(self.input, "{command}")?;
        writeln!(self.input, "printf '\\036{}:%d\\037\\n' \"$?\"", marker)?;
        self.input.flush()?;

        let prefix = format!("\u{1e}{marker}:");
        let mut collected = Vec::new();
        loop {
            let mut line = Vec::new();
            if self.output.read_until(b'\n', &mut line)? == 0 {
                bail!("shell process exited");
            }
            if let Some((output_end, status)) = completion_in(&line, prefix.as_bytes()) {
                collected.extend_from_slice(&line[..output_end]);
                return Ok((String::from_utf8_lossy(&collected).into_owned(), status));
            }
            collected.extend_from_slice(&line);
            if collected.len() > 16 * 1024 * 1024 {
                bail!("command output exceeded 16 MiB");
            }
        }
    }
}

impl Drop for ShellSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn completion_in(chunk: &[u8], prefix: &[u8]) -> Option<(usize, i32)> {
    let marker_start = chunk
        .windows(prefix.len())
        .position(|window| window == prefix)?;
    let status_start = marker_start + prefix.len();
    let status_end = status_start
        + chunk[status_start..]
            .iter()
            .position(|byte| *byte == 0x1f)?;
    let status = std::str::from_utf8(&chunk[status_start..status_end])
        .ok()?
        .parse()
        .ok()?;
    Some((marker_start, status))
}

#[cfg(test)]
mod tests {
    use super::{ShellSession, completion_in};

    #[test]
    fn finds_completion_after_output_without_a_newline() {
        let chunk = b"\x1b[H\x1b[2J\x1b[3J\x1eSHEX-test:0\x1f\n";
        assert_eq!(completion_in(chunk, b"\x1eSHEX-test:"), Some((11, 0)));
    }

    #[test]
    fn ignores_an_incomplete_completion_marker() {
        assert_eq!(
            completion_in(b"output\x1eSHEX-test:0", b"\x1eSHEX-test:"),
            None
        );
    }

    #[test]
    fn shell_handles_commands_without_trailing_newlines() {
        let mut shell = ShellSession::spawn().unwrap();
        let (plain, plain_status) = shell.run("printf 'no newline'").unwrap();
        assert_eq!((plain.as_str(), plain_status), ("no newline", 0));

        let (clear, clear_status) = shell.run("printf '\\033[H\\033[2J\\033[3J'").unwrap();
        assert_eq!(
            (clear.as_bytes(), clear_status),
            (b"\x1b[H\x1b[2J\x1b[3J".as_slice(), 0)
        );
    }
}

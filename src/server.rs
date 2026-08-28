use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
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
};

type Sessions = Arc<Mutex<HashMap<String, Arc<Mutex<ShellSession>>>>>;

pub fn serve(bind: SocketAddr, data_dir: &Path) -> Result<()> {
    let credentials = Arc::new(ServerCredentials::load(data_dir)?);
    let listener = TcpListener::bind(bind).with_context(|| format!("could not bind {bind}"))?;
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    eprintln!("shex listening on {bind}");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let credentials = credentials.clone();
                let sessions = sessions.clone();
                thread::spawn(move || {
                    if let Err(error) = handle(stream, &credentials, &sessions) {
                        eprintln!("connection ended: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

fn handle(stream: TcpStream, credentials: &ServerCredentials, sessions: &Sessions) -> Result<()> {
    stream.set_nodelay(true)?;
    let (stream, key) = auth::server_login(stream, credentials).context("authentication failed")?;
    let mut channel = SecureChannel::server(stream, &key)?;
    channel.send(&ServerReply::Hello {
        server_signature: credentials.signature().to_owned(),
    })?;

    let requested = match channel.recv::<ClientRequest>()? {
        ClientRequest::Open { session } => session,
        _ => bail!("the first request must open a session"),
    };

    let (id, shell) = match requested {
        Some(id) => {
            let shell = sessions.lock().unwrap().get(&id).cloned();
            match shell {
                Some(shell) => (id, shell),
                None => {
                    channel.send(&ServerReply::Error {
                        message: "unknown session".into(),
                    })?;
                    return Ok(());
                }
            }
        }
        None => {
            let id = random_id();
            let shell = Arc::new(Mutex::new(ShellSession::spawn()?));
            sessions.lock().unwrap().insert(id.clone(), shell.clone());
            (id, shell)
        }
    };
    channel.send(&ServerReply::Opened { session: id })?;

    loop {
        match channel.recv::<ClientRequest>() {
            Ok(ClientRequest::Run { command }) => {
                let result = shell.lock().unwrap().run(&command);
                match result {
                    Ok((data, status)) => channel.send(&ServerReply::Output { data, status })?,
                    Err(error) => channel.send(&ServerReply::Error {
                        message: format!("{error:#}"),
                    })?,
                }
            }
            Ok(ClientRequest::Open { .. }) => channel.send(&ServerReply::Error {
                message: "session is already open".into(),
            })?,
            Err(error) if is_disconnect(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
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
    _child: Child,
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
            _child: child,
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

mod auth;
mod auth_file;
mod channel;
mod credential_store;
mod protocol;
mod redis_store;
mod redis_transport;
mod server;

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use auth_file::{AuthFile, StoredAuth};
use channel::SecureChannel;
use clap::{Parser, Subcommand};
use protocol::{ClientRequest, ServerReply};

#[derive(Parser)]
#[command(name = "shex", version, about = "Zero-knowledge Redis remote shell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create local host credentials.
    Init {
        #[arg(long, default_value = ".shex")]
        data_dir: PathBuf,
    },
    /// Host encrypted shell sessions through Redis.
    Serve {
        #[arg(long, env = "REDIS_URL", hide_env_values = true)]
        redis_url: Option<String>,
        /// Permanent Redis hostname; generated and saved on first use if omitted.
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long, default_value = ".shex")]
        data_dir: PathBuf,
    },
    /// Authenticate once and save this host under ~/.shex.
    #[command(name = "auth", visible_alias = "authenticate")]
    Auth {
        hostname: String,
        #[arg(long, env = "REDIS_URL", hide_env_values = true)]
        redis_url: Option<String>,
        #[arg(long)]
        code_stdin: bool,
        #[arg(long, default_value_os_t = auth_file::default_store_dir())]
        store_dir: PathBuf,
    },
    /// Open an interactive shell using saved host authentication.
    Connect {
        hostname: String,
        #[arg(long, env = "REDIS_URL", hide_env_values = true)]
        redis_url: Option<String>,
        #[arg(long)]
        auth_file: Option<PathBuf>,
        #[arg(long, default_value_os_t = auth_file::default_store_dir())]
        store_dir: PathBuf,
        #[arg(long)]
        session: Option<String>,
        /// Bypass saved authentication and read a code from stdin.
        #[arg(long)]
        code_stdin: bool,
    },
    /// Execute a command using a saved host, e.g. `shex exec HOST pwd`.
    Exec {
        /// Use a legacy or explicitly selected auth file instead of HOST.
        #[arg(long)]
        auth_file: Option<PathBuf>,
        #[arg(long, default_value_os_t = auth_file::default_store_dir())]
        store_dir: PathBuf,
        #[arg(long, conflicts_with = "past")]
        session: Option<String>,
        #[arg(long, conflicts_with = "session")]
        past: bool,
        #[arg(required = true, trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Delete a persistent session from its host and Redis lookup layer.
    Close {
        hostname: Option<String>,
        #[arg(long)]
        auth_file: Option<PathBuf>,
        #[arg(long, default_value_os_t = auth_file::default_store_dir())]
        store_dir: PathBuf,
        /// Session to delete; defaults to the last session in the auth file.
        #[arg(long)]
        session: Option<String>,
    },
    /// Measure Redis and encrypted host round-trip latency.
    Latency {
        #[command(subcommand)]
        action: LatencyAction,
    },
    /// Manage locally saved Redis servers.
    Redis {
        #[command(subcommand)]
        action: RedisAction,
    },
}

#[derive(Subcommand)]
enum LatencyAction {
    /// Run latency samples. Add HOST to include its encrypted round trip.
    Test {
        hostname: Option<String>,
        #[arg(long, env = "REDIS_URL", hide_env_values = true)]
        redis_url: Option<String>,
        #[arg(long)]
        auth_file: Option<PathBuf>,
        #[arg(long, default_value_os_t = auth_file::default_store_dir())]
        store_dir: PathBuf,
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=100))]
        count: u32,
    },
}

#[derive(Subcommand)]
enum RedisAction {
    /// Save or update a named Redis URL in secure credential storage.
    Add {
        name: Option<String>,
        #[arg(env = "REDIS_URL", hide_env_values = true)]
        redis_url: Option<String>,
        #[arg(long, default_value_os_t = auth_file::default_store_dir())]
        store_dir: PathBuf,
    },
}

fn read_code(force_stdin: bool, confirm: bool) -> Result<Vec<u8>> {
    let code = if force_stdin || !io::stdin().is_terminal() {
        let mut value = String::new();
        io::stdin().read_line(&mut value)?;
        value.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        rpassword::prompt_password("Authentication code: ")?
    };
    if code.is_empty() {
        bail!("the authentication code cannot be empty");
    }
    if confirm && io::stdin().is_terminal() && !force_stdin {
        let second = rpassword::prompt_password("Confirm code: ")?;
        if code != second {
            bail!("codes do not match");
        }
    }
    Ok(code.into_bytes())
}

fn prompt_line(label: &str) -> Result<String> {
    eprint!("{label}");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("a value is required");
    }
    Ok(value)
}

fn prompt_redis_url() -> Result<String> {
    if io::stdin().is_terminal() {
        let value = rpassword::prompt_password("Redis URL: ")?;
        if value.trim().is_empty() {
            bail!("a Redis URL is required");
        }
        Ok(value.trim().to_owned())
    } else {
        prompt_line("Redis URL: ")
    }
}

fn confirm_save_unreachable() -> Result<bool> {
    eprint!("Save this server anyway? [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    match cli.command {
        Command::Init { data_dir } => {
            let code = read_code(false, true)?;
            auth::initialize(&data_dir, &code)?;
            println!("initialized {}", data_dir.display());
        }
        Command::Serve {
            redis_url,
            hostname,
            data_dir,
        } => {
            let redis_url = redis_store::resolve_or_default(
                &auth_file::default_store_dir(),
                redis_url.as_deref(),
            )?;
            server::serve(&redis_url, hostname.as_deref(), &data_dir)?;
        }
        Command::Auth {
            hostname,
            redis_url,
            code_stdin,
            store_dir,
        } => {
            let redis_url = redis_store::resolve_or_default(&store_dir, redis_url.as_deref())?;
            let code = read_code(code_stdin, false)?;
            let (mut channel, server_signature) =
                client_channel(&redis_url, &hostname, &code, None)?;
            channel.send(&ClientRequest::Disconnect)?;
            let auth = AuthFile::create_for_host(
                StoredAuth {
                    redis_url,
                    hostname,
                    server_signature,
                    code,
                    last_session: None,
                },
                &store_dir,
            )?;
            println!("authentication saved to {}", auth.path().display());
        }
        Command::Connect {
            hostname,
            redis_url,
            auth_file,
            store_dir,
            session,
            code_stdin,
        } => {
            let mut channel = if code_stdin {
                let code = read_code(true, false)?;
                let redis_url = redis_store::resolve_or_default(&store_dir, redis_url.as_deref())?;
                client_channel(&redis_url, &hostname, &code, None)?.0
            } else {
                let saved = load_host_auth(auth_file.as_deref(), &store_dir, &hostname)?;
                let reference = redis_url.as_deref().unwrap_or(&saved.data.redis_url);
                let redis_url = redis_store::resolve(&store_dir, reference)?;
                client_channel(
                    &redis_url,
                    &hostname,
                    &saved.data.code,
                    Some(&saved.data.server_signature),
                )?
                .0
            };
            let persistent = session.is_some();
            let session = open_session(&mut channel, session, persistent)?;
            eprintln!("session: {session}");
            interactive(&mut channel)?;
        }
        Command::Exec {
            auth_file,
            store_dir,
            session,
            past,
            args,
        } => {
            let (hostname, command) = split_exec_args(args, auth_file.is_some())?;
            let mut saved = match auth_file.as_deref() {
                Some(path) => AuthFile::load(path)?,
                None => AuthFile::load_for_host(
                    &store_dir,
                    hostname.as_deref().expect("hostname checked above"),
                )?,
            };
            let requested_session = if past {
                Some(
                    saved
                        .data
                        .last_session
                        .clone()
                        .context("this auth file has no previous session")?,
                )
            } else {
                session
            };
            let (mut channel, _) = client_channel(
                &saved.data.redis_url,
                &saved.data.hostname,
                &saved.data.code,
                Some(&saved.data.server_signature),
            )?;
            let session = open_session(&mut channel, requested_session, true)?;
            saved.data.last_session = Some(session.clone());
            saved.save()?;
            eprintln!("session: {session}");
            execute(&mut channel, command.join(" "))?;
        }
        Command::Close {
            hostname,
            auth_file,
            store_dir,
            session,
        } => {
            let mut saved = match auth_file.as_deref() {
                Some(path) => AuthFile::load(path)?,
                None => {
                    let hostname = hostname
                        .as_deref()
                        .context("pass a hostname or use `--auth-file`")?;
                    AuthFile::load_for_host(&store_dir, hostname)?
                }
            };
            let session = session
                .or_else(|| saved.data.last_session.clone())
                .context("this auth file has no previous session; pass `--session`")?;
            let (mut channel, _) = client_channel(
                &saved.data.redis_url,
                &saved.data.hostname,
                &saved.data.code,
                Some(&saved.data.server_signature),
            )?;
            channel.send(&ClientRequest::DeleteSession {
                session: session.clone(),
            })?;
            match channel.recv::<ServerReply>()? {
                ServerReply::Deleted { session: deleted } if deleted == session => {}
                ServerReply::Error { message } => bail!("server: {message}"),
                other => bail!("unexpected server response: {other:?}"),
            }
            if saved.data.last_session.as_deref() == Some(&session) {
                saved.data.last_session = None;
                saved.save()?;
            }
            println!("deleted session {session}");
        }
        Command::Latency {
            action:
                LatencyAction::Test {
                    hostname,
                    redis_url,
                    auth_file,
                    store_dir,
                    count,
                },
        } => {
            let saved = match (auth_file.as_deref(), hostname.as_deref()) {
                (Some(path), _) => Some(AuthFile::load(path)?),
                (None, Some(hostname)) => Some(AuthFile::load_for_host(&store_dir, hostname)?),
                (None, None) => None,
            };
            if let (Some(requested), Some(saved)) = (hostname.as_deref(), saved.as_ref())
                && requested != saved.data.hostname
            {
                bail!(
                    "the selected auth file belongs to `{}`",
                    saved.data.hostname
                );
            }
            let redis_reference =
                redis_url.or_else(|| saved.as_ref().map(|auth| auth.data.redis_url.clone()));
            let redis_url =
                redis_store::resolve_or_default(&store_dir, redis_reference.as_deref())?;
            let redis_stats = redis_transport::measure_latency(&redis_url, count)?;
            print_latency("Redis round trip", &redis_stats);

            if let Some(saved) = saved {
                let host_stats = measure_host_latency(&saved, &redis_url, count)?;
                print_latency("Host round trip through Redis", &host_stats);
                println!(
                    "Additional encrypted host path (estimate): {:.2} ms",
                    host_stats
                        .average
                        .saturating_sub(redis_stats.average)
                        .as_secs_f64()
                        * 1000.0
                );
            } else {
                println!("Host round trip: skipped (pass a saved hostname)");
            }
        }
        Command::Redis {
            action:
                RedisAction::Add {
                    name,
                    redis_url,
                    store_dir,
                },
        } => {
            let name = match name {
                Some(name) => name,
                None => prompt_line("Redis server name: ")?,
            };
            let redis_url = match redis_url {
                Some(redis_url) => redis_url,
                None => prompt_redis_url()?,
            };
            redis::Client::open(redis_url.as_str()).context("invalid Redis URL")?;
            match redis_transport::measure_latency(&redis_url, 1) {
                Ok(stats) => print_latency("Redis connection verified", &stats),
                Err(error) => {
                    eprintln!("Redis connection test failed: {error:#}");
                    if !confirm_save_unreachable()? {
                        println!("Redis server was not saved");
                        return Ok(());
                    }
                }
            }
            let path = redis_store::add(&store_dir, &name, &redis_url)?;
            println!("saved Redis server `{name}` in {}", path.display());
            if let Some(notice) = credential_store::fallback_notice() {
                println!("{notice}");
            }
        }
    }
    Ok(())
}

fn load_host_auth(auth_path: Option<&Path>, store_dir: &Path, hostname: &str) -> Result<AuthFile> {
    let auth = match auth_path {
        Some(path) => AuthFile::load(path)?,
        None => AuthFile::load_for_host(store_dir, hostname)?,
    };
    if auth.data.hostname != hostname {
        bail!("the selected auth file belongs to `{}`", auth.data.hostname);
    }
    Ok(auth)
}

fn split_exec_args(
    mut args: Vec<String>,
    explicit_auth_file: bool,
) -> Result<(Option<String>, Vec<String>)> {
    let hostname = if explicit_auth_file {
        None
    } else {
        if args.len() < 2 {
            bail!("usage: shex exec <HOSTNAME> <COMMAND>...");
        }
        Some(args.remove(0))
    };
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    }
    if args.is_empty() {
        bail!("a command is required");
    }
    Ok((hostname, args))
}

fn measure_host_latency(
    saved: &AuthFile,
    redis_url: &str,
    count: u32,
) -> Result<redis_transport::LatencyStats> {
    let (mut channel, _) = client_channel(
        redis_url,
        &saved.data.hostname,
        &saved.data.code,
        Some(&saved.data.server_signature),
    )?;
    channel.send(&ClientRequest::Ping)?;
    match channel.recv::<ServerReply>()? {
        ServerReply::Pong => {}
        other => bail!("unexpected host latency response: {other:?}"),
    }

    let mut samples = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let started = Instant::now();
        channel.send(&ClientRequest::Ping)?;
        match channel.recv::<ServerReply>()? {
            ServerReply::Pong => samples.push(started.elapsed()),
            other => bail!("unexpected host latency response: {other:?}"),
        }
    }
    channel.send(&ClientRequest::Disconnect)?;
    let minimum = *samples.iter().min().expect("latency samples are non-empty");
    let maximum = *samples.iter().max().expect("latency samples are non-empty");
    let total: Duration = samples.iter().copied().sum();
    Ok(redis_transport::LatencyStats {
        minimum,
        average: total / count,
        maximum,
    })
}

fn print_latency(label: &str, stats: &redis_transport::LatencyStats) {
    println!(
        "{label}: avg {:.2} ms (min {:.2}, max {:.2})",
        stats.average.as_secs_f64() * 1000.0,
        stats.minimum.as_secs_f64() * 1000.0,
        stats.maximum.as_secs_f64() * 1000.0,
    );
}

fn client_channel(
    redis_url: &str,
    hostname: &str,
    code: &[u8],
    expected_signature: Option<&str>,
) -> Result<(SecureChannel, String)> {
    let mut transport = redis_transport::RedisTransport::client(redis_url, hostname)?;
    let key = auth::client_login(&mut transport, code).context("authentication failed")?;
    let mut channel = SecureChannel::client(Box::new(transport), &key)?;
    let signature = match channel.recv::<ServerReply>()? {
        ServerReply::Hello { server_signature } => server_signature,
        other => bail!("expected server identity, received {other:?}"),
    };
    if expected_signature.is_some_and(|expected| expected != signature) {
        bail!("server signature does not match this auth file");
    }
    Ok((channel, signature))
}

fn open_session(
    channel: &mut SecureChannel,
    session: Option<String>,
    persistent: bool,
) -> Result<String> {
    channel.send(&ClientRequest::Open {
        session,
        persistent,
    })?;
    match channel.recv::<ServerReply>()? {
        ServerReply::Opened { session } => Ok(session),
        ServerReply::Error { message } => bail!("server: {message}"),
        other => bail!("unexpected server response: {other:?}"),
    }
}

fn execute(channel: &mut SecureChannel, command: String) -> Result<()> {
    channel.wait_indefinitely();
    channel.send(&ClientRequest::Run { command })?;
    match channel.recv_unacknowledged::<ServerReply>()? {
        ServerReply::Output { data, status } => {
            print!("{data}");
            io::stdout().flush()?;
            channel.acknowledge()?;
            channel.send(&ClientRequest::Disconnect)?;
            if status != 0 {
                std::process::exit(status.clamp(1, 255));
            }
        }
        ServerReply::Error { message } => {
            channel.acknowledge()?;
            bail!("server: {message}")
        }
        other => bail!("unexpected server response: {other:?}"),
    }
    Ok(())
}

fn interactive(channel: &mut SecureChannel) -> Result<()> {
    channel.wait_indefinitely();
    let mut line = String::new();
    loop {
        eprint!("shex> ");
        io::stderr().flush()?;
        line.clear();
        if io::stdin().read_line(&mut line)? == 0 {
            channel.send(&ClientRequest::Disconnect)?;
            break;
        }
        let command = line.trim_end().to_owned();
        if command == "exit" {
            channel.send(&ClientRequest::Disconnect)?;
            break;
        }
        if command.is_empty() {
            continue;
        }
        channel.send(&ClientRequest::Run { command })?;
        match channel.recv_unacknowledged::<ServerReply>()? {
            ServerReply::Output { data, .. } => {
                print!("{data}");
                io::stdout().flush()?;
                channel.acknowledge()?;
            }
            ServerReply::Error { message } => {
                eprintln!("server: {message}");
                channel.acknowledge()?;
            }
            other => bail!("unexpected server response: {other:?}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::{Cli, Command, LatencyAction, RedisAction, split_exec_args};
    use clap::Parser;

    #[test]
    fn parses_hostname_first_exec() {
        let cli = Cli::try_parse_from(["shex", "exec", "random-name:1838", "--", "pwd"]).unwrap();
        let Command::Exec { args, .. } = cli.command else {
            panic!("expected exec command");
        };
        assert_eq!(args, ["random-name:1838", "--", "pwd"]);
        let (hostname, command) = split_exec_args(args, false).unwrap();
        assert_eq!(hostname.as_deref(), Some("random-name:1838"));
        assert_eq!(command, ["pwd"]);
    }

    #[test]
    fn parses_short_auth_command() {
        let cli = Cli::try_parse_from(["shex", "auth", "random-name:1838"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parses_latency_test_with_host() {
        let cli = Cli::try_parse_from([
            "shex",
            "latency",
            "test",
            "random-name:1838",
            "--count",
            "3",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Latency {
                action: LatencyAction::Test { count: 3, .. }
            }
        ));
    }

    #[test]
    fn parses_local_redis_add() {
        let cli =
            Cli::try_parse_from(["shex", "redis", "add", "local", "redis://127.0.0.1/"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Redis {
                action: RedisAction::Add { name, .. }
            } if name.as_deref() == Some("local")
        ));
    }

    #[test]
    fn parses_interactive_redis_add_without_arguments() {
        let cli = Cli::try_parse_from(["shex", "redis", "add"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Redis {
                action: RedisAction::Add { name: None, .. }
            }
        ));
    }
}

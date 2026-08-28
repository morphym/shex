mod auth;
mod auth_file;
mod channel;
mod protocol;
mod server;

use std::{
    io::{self, IsTerminal, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use auth_file::{AuthFile, StoredAuth};
use channel::SecureChannel;
use clap::{Parser, Subcommand};
use protocol::{ClientRequest, ServerReply};

#[derive(Parser)]
#[command(name = "shex", version, about = "Small encrypted remote shell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create server credentials. The code is never retained by the server.
    Init {
        #[arg(long, default_value = ".shex")]
        data_dir: PathBuf,
    },
    /// Listen for authenticated shell connections.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8022")]
        bind: SocketAddr,
        #[arg(long, default_value = ".shex")]
        data_dir: PathBuf,
    },
    /// Authenticate once and create an encrypted, server-bound local auth file.
    Authenticate {
        #[arg(default_value = "127.0.0.1:8022")]
        address: SocketAddr,
        /// Read the authentication code from standard input instead of a TTY prompt.
        #[arg(long)]
        code_stdin: bool,
    },
    /// Open an interactive shell, optionally resuming an existing session.
    Connect {
        #[arg(default_value = "127.0.0.1:8022")]
        address: SocketAddr,
        #[arg(long)]
        session: Option<String>,
        /// Read the authentication code from standard input instead of a TTY prompt.
        #[arg(long)]
        code_stdin: bool,
    },
    /// Execute a command using a saved authentication file.
    Exec {
        /// Encrypted auth file to use.
        #[arg(long, default_value = ".shex_auth")]
        auth_file: PathBuf,
        /// Resume this exact server-side shell session.
        #[arg(long, conflicts_with = "past")]
        session: Option<String>,
        /// Resume the last session recorded in the auth file.
        #[arg(long, conflicts_with = "session")]
        past: bool,
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { data_dir } => {
            let code = read_code(false, true)?;
            auth::initialize(&data_dir, &code)?;
            println!("initialized {}", data_dir.display());
        }
        Command::Serve { bind, data_dir } => server::serve(bind, &data_dir)?,
        Command::Authenticate {
            address,
            code_stdin,
        } => {
            let code = read_code(code_stdin, false)?;
            let (_, server_signature) = client_channel(address, &code, None)?;
            let auth = AuthFile::create(StoredAuth {
                address,
                server_signature,
                code,
                last_session: None,
            })?;
            println!("authentication saved to {}", auth.path().display());
            if auth.path() != std::path::Path::new(".shex_auth") {
                println!(
                    "an auth file already existed; pass `--auth-file {}` to `shex exec`",
                    auth.path().display()
                );
            }
        }
        Command::Connect {
            address,
            session,
            code_stdin,
        } => {
            let code = read_code(code_stdin, false)?;
            let (mut channel, _) = client_channel(address, &code, None)?;
            let session = open_session(&mut channel, session)?;
            eprintln!("session: {session}");
            interactive(&mut channel)?;
        }
        Command::Exec {
            auth_file,
            session,
            past,
            command,
        } => {
            let mut saved = AuthFile::load(&auth_file)?;
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
                saved.data.address,
                &saved.data.code,
                Some(&saved.data.server_signature),
            )?;
            let session = open_session(&mut channel, requested_session)?;
            saved.data.last_session = Some(session.clone());
            saved.save()?;
            eprintln!("session: {session}");
            execute(&mut channel, command.join(" "))?;
        }
    }
    Ok(())
}

fn client_channel(
    address: SocketAddr,
    code: &[u8],
    expected_signature: Option<&str>,
) -> Result<(SecureChannel, String)> {
    let stream =
        TcpStream::connect(address).with_context(|| format!("could not connect to {address}"))?;
    stream.set_nodelay(true)?;
    let (stream, key) = auth::client_login(stream, code).context("authentication failed")?;
    let mut channel = SecureChannel::client(stream, &key)?;
    let signature = match channel.recv::<ServerReply>()? {
        ServerReply::Hello { server_signature } => server_signature,
        other => bail!("expected server identity, received {other:?}"),
    };
    if expected_signature.is_some_and(|expected| expected != signature) {
        bail!("server signature does not match this auth file");
    }
    Ok((channel, signature))
}

fn open_session(channel: &mut SecureChannel, session: Option<String>) -> Result<String> {
    channel.send(&ClientRequest::Open { session })?;
    match channel.recv::<ServerReply>()? {
        ServerReply::Opened { session } => Ok(session),
        ServerReply::Error { message } => bail!("server: {message}"),
        other => bail!("unexpected server response: {other:?}"),
    }
}

fn execute(channel: &mut SecureChannel, command: String) -> Result<()> {
    channel.send(&ClientRequest::Run { command })?;
    match channel.recv::<ServerReply>()? {
        ServerReply::Output { data, status } => {
            print!("{data}");
            io::stdout().flush()?;
            if status != 0 {
                std::process::exit(status.clamp(1, 255));
            }
        }
        ServerReply::Error { message } => bail!("server: {message}"),
        other => bail!("unexpected server response: {other:?}"),
    }
    Ok(())
}

fn interactive(channel: &mut SecureChannel) -> Result<()> {
    let mut line = String::new();
    loop {
        eprint!("shex> ");
        io::stderr().flush()?;
        line.clear();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let command = line.trim_end().to_owned();
        if command == "exit" {
            break;
        }
        if command.is_empty() {
            continue;
        }
        channel.send(&ClientRequest::Run { command })?;
        match channel.recv::<ServerReply>()? {
            ServerReply::Output { data, .. } => {
                print!("{data}");
                io::stdout().flush()?;
            }
            ServerReply::Error { message } => eprintln!("server: {message}"),
            other => bail!("unexpected server response: {other:?}"),
        }
    }
    Ok(())
}

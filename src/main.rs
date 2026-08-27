mod auth;
mod channel;
mod protocol;
mod server;

use std::{
    io::{self, IsTerminal},
    net::SocketAddr,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

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
    /// Run one command without an interactive terminal.
    Exec {
        #[arg(long, default_value = "127.0.0.1:8022")]
        address: SocketAddr,
        /// Resume this server-side shell session.
        #[arg(long)]
        session: String,
        /// Read the authentication code from standard input before executing the command.
        #[arg(long)]
        code_stdin: bool,
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
        Command::Connect {
            address,
            session,
            code_stdin,
        } => {
            let code = read_code(code_stdin, false)?;
            run_client(address, &code, session, None)?;
        }
        Command::Exec {
            address,
            session,
            code_stdin,
            command,
        } => {
            let code = read_code(code_stdin, false)?;
            run_client(address, &code, Some(session), Some(command.join(" ")))?;
        }
    }
    Ok(())
}

fn run_client(
    address: SocketAddr,
    code: &[u8],
    session: Option<String>,
    command: Option<String>,
) -> Result<()> {
    use protocol::{ClientRequest, ServerReply};
    use std::io::Write;

    let stream = std::net::TcpStream::connect(address)
        .with_context(|| format!("could not connect to {address}"))?;
    stream.set_nodelay(true)?;
    let (stream, key) = auth::client_login(stream, code).context("authentication failed")?;
    let mut channel = channel::SecureChannel::client(stream, &key)?;

    channel.send(&ClientRequest::Open { session })?;
    let session_id = match channel.recv::<ServerReply>()? {
        ServerReply::Opened { session } => session,
        ServerReply::Error { message } => bail!("server: {message}"),
        other => bail!("unexpected server response: {other:?}"),
    };
    eprintln!("session: {session_id}");

    if let Some(command) = command {
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
        return Ok(());
    }

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

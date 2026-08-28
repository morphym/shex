use std::{fs, net::TcpStream, path::Path};

use anyhow::{Context, Result};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh, argon2::Argon2,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256, Sha512};

use crate::channel::{read_frame, write_frame};

pub struct ShexSuite;

impl CipherSuite for ShexSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

const IDENTITY: &[u8] = b"shex-user-v1";
const SETUP_FILE: &str = "server.setup";
const PASSWORD_FILE: &str = "password.record";

pub fn initialize(data_dir: &Path, code: &[u8]) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    let mut rng = OsRng;
    let setup = ServerSetup::<ShexSuite>::new(&mut rng);

    // Local OPAQUE registration: only the resulting password record is persisted.
    let client = ClientRegistration::<ShexSuite>::start(&mut rng, code)?;
    let server = ServerRegistration::<ShexSuite>::start(&setup, client.message, IDENTITY)?;
    let upload = client.state.finish(
        &mut rng,
        code,
        server.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let record = ServerRegistration::<ShexSuite>::finish(upload.message);

    write_private(&data_dir.join(SETUP_FILE), &setup.serialize())?;
    write_private(&data_dir.join(PASSWORD_FILE), &record.serialize())?;
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

pub struct ServerCredentials {
    setup: ServerSetup<ShexSuite>,
    record: ServerRegistration<ShexSuite>,
    signature: String,
}

impl ServerCredentials {
    pub fn load(data_dir: &Path) -> Result<Self> {
        let setup = fs::read(data_dir.join(SETUP_FILE))
            .context("missing server setup; run `shex init` first")?;
        let record = fs::read(data_dir.join(PASSWORD_FILE))
            .context("missing password record; run `shex init` first")?;
        let signature = Sha256::digest(&setup)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Self {
            setup: ServerSetup::deserialize(&setup)?,
            record: ServerRegistration::deserialize(&record)?,
            signature,
        })
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

pub fn client_login(mut stream: TcpStream, code: &[u8]) -> Result<(TcpStream, Vec<u8>)> {
    let mut rng = OsRng;
    let start = ClientLogin::<ShexSuite>::start(&mut rng, code)?;
    write_frame(&mut stream, &start.message.serialize())?;

    let response = CredentialResponse::<ShexSuite>::deserialize(&read_frame(&mut stream)?)?;
    let finish = start.state.finish(
        &mut rng,
        code,
        response,
        ClientLoginFinishParameters::default(),
    )?;
    write_frame(&mut stream, &finish.message.serialize())?;
    Ok((stream, finish.session_key.to_vec()))
}

pub fn server_login(
    mut stream: TcpStream,
    credentials: &ServerCredentials,
) -> Result<(TcpStream, Vec<u8>)> {
    let request = CredentialRequest::<ShexSuite>::deserialize(&read_frame(&mut stream)?)?;
    let mut rng = OsRng;
    let start = ServerLogin::start(
        &mut rng,
        &credentials.setup,
        Some(credentials.record.clone()),
        request,
        IDENTITY,
        ServerLoginParameters::default(),
    )?;
    write_frame(&mut stream, &start.message.serialize())?;

    let finalization = CredentialFinalization::<ShexSuite>::deserialize(&read_frame(&mut stream)?)?;
    let finish = start
        .state
        .finish(finalization, ServerLoginParameters::default())?;
    Ok((stream, finish.session_key.to_vec()))
}

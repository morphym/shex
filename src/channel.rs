use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

pub struct SecureChannel {
    stream: TcpStream,
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_counter: u64,
    recv_counter: u64,
    send_label: &'static [u8],
    recv_label: &'static [u8],
}

impl SecureChannel {
    pub fn client(stream: TcpStream, key: &[u8]) -> Result<Self> {
        Self::new(stream, key, b"client->server", b"server->client")
    }
    pub fn server(stream: TcpStream, key: &[u8]) -> Result<Self> {
        Self::new(stream, key, b"server->client", b"client->server")
    }
    fn new(
        stream: TcpStream,
        key: &[u8],
        send_label: &'static [u8],
        recv_label: &'static [u8],
    ) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(b"shex transport v1"), key);
        let mut c2s = [0u8; 32];
        let mut s2c = [0u8; 32];
        hk.expand(b"client->server", &mut c2s)
            .map_err(|_| anyhow::anyhow!("HKDF failure"))?;
        hk.expand(b"server->client", &mut s2c)
            .map_err(|_| anyhow::anyhow!("HKDF failure"))?;
        let (send_key, recv_key) = if send_label == b"client->server" {
            (&c2s, &s2c)
        } else {
            (&s2c, &c2s)
        };
        Ok(Self {
            stream,
            send: ChaCha20Poly1305::new(send_key.into()),
            recv: ChaCha20Poly1305::new(recv_key.into()),
            send_counter: 0,
            recv_counter: 0,
            send_label,
            recv_label,
        })
    }
    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }
    pub fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let plain = serde_json::to_vec(value)?;
        let nonce = Self::nonce(self.send_counter);
        let encrypted = self
            .send
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plain,
                    aad: self.send_label,
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .context("message counter exhausted")?;
        write_frame(&mut self.stream, &encrypted)
    }
    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        let encrypted = read_frame(&mut self.stream)?;
        let nonce = Self::nonce(self.recv_counter);
        let plain = self
            .recv
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &encrypted,
                    aad: self.recv_label,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypted message was invalid"))?;
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .context("message counter exhausted")?;
        Ok(serde_json::from_slice(&plain)?)
    }
}

pub fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    if data.len() > 16 * 1024 * 1024 {
        bail!("frame too large");
    }
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

pub fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 16 * 1024 * 1024 {
        bail!("frame too large");
    }
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data)?;
    Ok(data)
}

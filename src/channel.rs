use anyhow::{Context, Result};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

pub trait FrameTransport: Send {
    fn send_frame(&mut self, data: &[u8]) -> Result<()>;
    fn recv_frame(&mut self) -> Result<Vec<u8>>;
    fn acknowledge(&mut self) -> Result<()>;
    fn wait_indefinitely(&mut self);
}

pub struct SecureChannel {
    transport: Box<dyn FrameTransport>,
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_counter: u64,
    recv_counter: u64,
    send_label: &'static [u8],
    recv_label: &'static [u8],
}

impl SecureChannel {
    pub fn client(transport: Box<dyn FrameTransport>, key: &[u8]) -> Result<Self> {
        Self::new(transport, key, b"client->server", b"server->client")
    }

    pub fn server(transport: Box<dyn FrameTransport>, key: &[u8]) -> Result<Self> {
        Self::new(transport, key, b"server->client", b"client->server")
    }

    fn new(
        transport: Box<dyn FrameTransport>,
        key: &[u8],
        send_label: &'static [u8],
        recv_label: &'static [u8],
    ) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(b"shex transport v2"), key);
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
            transport,
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
        self.transport.send_frame(&encrypted)?;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .context("message counter exhausted")?;
        Ok(())
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        let value = self.recv_unacknowledged()?;
        self.acknowledge()?;
        Ok(value)
    }

    pub fn recv_unacknowledged<T: DeserializeOwned>(&mut self) -> Result<T> {
        let encrypted = self.transport.recv_frame()?;
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
        Ok(serde_json::from_slice(&plain)?)
    }

    pub fn acknowledge(&mut self) -> Result<()> {
        self.transport.acknowledge()?;
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .context("message counter exhausted")?;
        Ok(())
    }

    pub fn wait_indefinitely(&mut self) {
        self.transport.wait_indefinitely();
    }
}

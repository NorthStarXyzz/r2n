use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadInPlace, KeyInit},
};
use snow::params::NoiseParams;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Snow error: {0}")]
    Snow(#[from] snow::Error),
    #[error("AEAD error")]
    Aead,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Noise pattern: IK (Interactive, pre-shared public keys)
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

pub struct NoiseSession {
    inner: snow::HandshakeState,
}

impl NoiseSession {
    pub fn initiator(local_priv: &[u8], remote_pub: &[u8]) -> Result<Self> {
        let params: NoiseParams = NOISE_PATTERN.parse()?;
        let builder = snow::Builder::new(params);
        let inner = builder
            .local_private_key(local_priv)
            .remote_public_key(remote_pub)
            .build_initiator()?;
        Ok(Self { inner })
    }

    pub fn responder(local_priv: &[u8]) -> Result<Self> {
        let params: NoiseParams = NOISE_PATTERN.parse()?;
        let builder = snow::Builder::new(params);
        let inner = builder.local_private_key(local_priv).build_responder()?;
        Ok(Self { inner })
    }

    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize> {
        self.inner
            .write_message(payload, message)
            .map_err(Into::into)
    }

    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize> {
        self.inner
            .read_message(message, payload)
            .map_err(Into::into)
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    pub fn into_transport_mode(self) -> Result<snow::TransportState> {
        self.inner.into_transport_mode().map_err(Into::into)
    }
}

pub struct Cipher {
    inner: ChaCha20Poly1305,
    window: std::sync::Mutex<ReplayWindow>,
}

struct ReplayWindow {
    last_nonce: u64,
    bitmap: u64,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: ChaCha20Poly1305::new(key.into()),
            window: std::sync::Mutex::new(ReplayWindow {
                last_nonce: 0,
                bitmap: 0,
            }),
        }
    }

    pub fn encrypt(&self, nonce: u64, payload: &[u8]) -> Result<Vec<u8>> {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&nonce.to_be_bytes());
        let nonce_p = Nonce::from_slice(&n);
        self.inner
            .encrypt(nonce_p, payload)
            .map_err(|_| CryptoError::Aead)
    }

    pub fn encrypt_in_place(
        &self,
        nonce: u64,
        aad: &[u8],
        buffer: &mut [u8],
        payload_len: usize,
    ) -> Result<usize> {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&nonce.to_be_bytes());
        let nonce_p = Nonce::from_slice(&n);
        let tag = self
            .inner
            .encrypt_in_place_detached(nonce_p, aad, &mut buffer[..payload_len])
            .map_err(|_| CryptoError::Aead)?;
        buffer[payload_len..payload_len + 16].copy_from_slice(&tag);
        Ok(payload_len + 16)
    }

    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.check_replay_window(nonce)?;
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&nonce.to_be_bytes());
        let nonce_p = Nonce::from_slice(&n);
        let decrypted = self
            .inner
            .decrypt(nonce_p, ciphertext)
            .map_err(|_| CryptoError::Aead)?;
        self.advance_replay_window(nonce);
        Ok(decrypted)
    }

    pub fn decrypt_in_place(&self, nonce: u64, aad: &[u8], buffer: &mut [u8]) -> Result<usize> {
        self.check_replay_window(nonce)?;
        if buffer.len() < 16 {
            return Err(CryptoError::Aead);
        }
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&nonce.to_be_bytes());
        let nonce_p = Nonce::from_slice(&n);

        let payload_len = buffer.len() - 16;
        let (payload, tag_bytes) = buffer.split_at_mut(payload_len);
        let tag = chacha20poly1305::aead::Tag::<ChaCha20Poly1305>::from_slice(tag_bytes);

        self.inner
            .decrypt_in_place_detached(nonce_p, aad, payload, tag)
            .map_err(|_| CryptoError::Aead)?;

        self.advance_replay_window(nonce);
        Ok(payload_len)
    }

    fn check_replay_window(&self, nonce: u64) -> Result<()> {
        let win = self.window.lock().unwrap();
        if nonce <= win.last_nonce {
            let diff = win.last_nonce - nonce;
            if diff >= 64 || (win.bitmap & (1 << diff)) != 0 {
                return Err(CryptoError::Aead);
            }
        }
        Ok(())
    }

    fn advance_replay_window(&self, nonce: u64) {
        let mut win = self.window.lock().unwrap();
        if nonce > win.last_nonce {
            let shift = (nonce - win.last_nonce).min(64);
            win.bitmap = (win.bitmap << shift) | 1;
            win.last_nonce = nonce;
        } else {
            let diff = win.last_nonce - nonce;
            win.bitmap |= 1 << diff;
        }
    }
}

pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    public.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inplace_encrypt_roundtrip() {
        let key = [7u8; 32];
        let cipher = Cipher::new(&key);
        let mut buffer = [0u8; 100];
        buffer[..9].copy_from_slice(b"hello-r2n");
        let encrypted_len = cipher
            .encrypt_in_place(1, b"aad", &mut buffer, 9)
            .expect("encrypt");
        assert_eq!(encrypted_len, 25);
        let decrypted_len = cipher
            .decrypt_in_place(1, b"aad", &mut buffer[..25])
            .expect("decrypt");
        assert_eq!(decrypted_len, 9);
        assert_eq!(&buffer[..9], b"hello-r2n");
    }
}

//! 32-byte secret material, wiped from memory on drop.

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a symmetric key (256 bits).
pub const KEY_LEN: usize = 32;

/// A 256-bit key/secret that wipes itself from memory on drop.
///
/// Deliberately does NOT derive `Clone`/`Debug`/`Serialize`: a secret must not
/// be copied or logged by accident.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Builds from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generates a random key via the system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        let key = Self(bytes);
        bytes.zeroize();
        key
    }

    /// Read-only access to the raw bytes (for encryption).
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

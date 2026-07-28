//! Known-answer tests (golden vectors).
//!
//! Every other crypto test in this crate is a round-trip: it encrypts and
//! decrypts with the same code, so a dependency upgrade that silently changed
//! an algorithm's output (argon2, hkdf, chacha20poly1305, x25519/ed25519) would
//! still pass while making every existing vault, message and safety number
//! unreadable/incompatible. These vectors pin the current, known-good outputs
//! so any such drift fails loudly.
//!
//! The values were generated once with the current implementation and frozen.
//! If a change here is intentional (a deliberate format/algorithm bump), update
//! the constant AND ship a migration — do not "fix the test" casually.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_core::kdf::{self, KdfParams};
use crypto_core::send::{open, safety_number, IdentityKeys, Sender};
use crypto_core::{AccountSecret, SendBlob};
use data_encoding::HEXLOWER;

fn kat_kdf() -> KdfParams {
    KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    }
}

/// Argon2id(master password, salt, params) → 256-bit master key.
#[test]
fn argon2id_master_key_vector() {
    let salt = [0x11u8; 16];
    let master = kdf::derive_master_key(b"correct horse battery staple", &salt, kat_kdf()).unwrap();
    assert_eq!(
        HEXLOWER.encode(master.as_bytes()),
        "064401872f712d299da5dc8fb3058e4af259cf62e8c3d78419ee23295cc88a19"
    );
}

/// HKDF sub-key derivation (wrap key + auth secret) from a fixed master key and
/// a fixed Secret Key. The formatted Secret Key is itself a checksum-validated
/// fixed input.
#[test]
fn hkdf_subkey_vectors() {
    let salt = [0x11u8; 16];
    let master = kdf::derive_master_key(b"correct horse battery staple", &salt, kat_kdf()).unwrap();
    let secret = AccountSecret::parse("A1-VRVKQ-QC43P-WQRVZ-RZC54-EV2YL-HPGY").unwrap();

    assert_eq!(
        HEXLOWER.encode(kdf::derive_wrap_key(&master, &secret).as_bytes()),
        "495845f04ad2f63f297f546c8ff1d7160dc8d90586b9289cdcaad138a0c8ceac"
    );
    assert_eq!(
        HEXLOWER.encode(kdf::derive_auth_secret(&master, &secret).as_bytes()),
        "cbd76093aeeaf8c177be9483cbb361ad9f07a37d174096fe05fc81cf9a60802f"
    );
}

/// The Signal-style safety number for two fixed identities. Any change here
/// silently breaks every user's already-verified contacts, so it is pinned.
#[test]
fn safety_number_vector() {
    let a = identity("Z20bqaZEjNhfzqhloPjZ9GgNcEe/v4Z2KK01BQgrXCqIhrJgQU+sTsrLJYNGegCZDI1yhHqyKjcPcUNTSUWDiAAAAAE=");
    let b = identity("FIFHbW1HHwxV9ficZFMN5AAnQAFrgGg9/LAWSJMlGLIAsDFmyAUGF/xt3ehOrLDfuiGYJImNAmQF1olIzeNvwgAAAAE=");
    assert_eq!(
        safety_number("AID", &a.public(), "BID", &b.public()),
        "587691311184857573331524917478725623570392281920211259276350"
    );
}

/// Format-stability: a signed Send blob serialized by an earlier build must
/// still open under the current code, yielding the original plaintext and the
/// Verified sender. Catches any incompatible change to the on-wire SendBlob
/// shape or the seal/open handshake.
#[test]
fn send_blob_format_is_stable() {
    let recipient = identity("FIFHbW1HHwxV9ficZFMN5AAnQAFrgGg9/LAWSJMlGLIAsDFmyAUGF/xt3ehOrLDfuiGYJImNAmQF1olIzeNvwgAAAAE=");
    let sender_public = identity("Z20bqaZEjNhfzqhloPjZ9GgNcEe/v4Z2KK01BQgrXCqIhrJgQU+sTsrLJYNGegCZDI1yhHqyKjcPcUNTSUWDiAAAAAE=").public();

    let blob: SendBlob = serde_json::from_str(FROZEN_SEND_BLOB).unwrap();
    let opened = open(&blob, &recipient, None, Some(&sender_public)).unwrap();
    assert_eq!(&*opened.plaintext, b"kat-plaintext");
    assert_eq!(opened.sender, Sender::Verified("AID".to_string()));
}

/// The lock-phrase (pinlock) record format. A drift in the Argon2id→HKDF lock
/// key chain, the commitment derivation, or the length-prefixed AAD framing
/// would make every stored locked record unopenable — round-trip tests cannot
/// see it because they re-derive both sides.
#[test]
fn locked_record_format_is_stable() {
    let phrase = b"orange kettle drum";
    let salt = [0x33u8; 16];

    let record: crypto_core::LockedRecord = serde_json::from_str(FROZEN_LOCKED_RECORD).unwrap();
    let opened = crypto_core::lock_open(&record, phrase, &salt, kat_kdf()).unwrap();
    assert_eq!(&*opened.plaintext, b"kat-plaintext");
    assert_eq!(opened.sender, Sender::Verified("AID".to_string()));

    // A wrong phrase fails closed at the commitment, with no plaintext.
    assert!(crypto_core::lock_open(&record, b"wrong phrase", &salt, kat_kdf()).is_err());
}

fn identity(b64: &str) -> IdentityKeys {
    IdentityKeys::from_bytes(&B64.decode(b64).unwrap()).unwrap()
}

// A signed blob produced by the current implementation and frozen.
const FROZEN_SEND_BLOB: &str = r#"{"v":1,"type":"send","message_id":"C0+YVgpEBKPL4jFtc12dZw==","recipient_id":"BID","recipient_enc_pub":"m3vakeXpSNXx8kxZvQiwTOai6l97CrjOhRjkAkq7q3A=","recipient_key_version":1,"eph_pub":"GXGH9em0zNu5Kz1NwT0Uob0+YuJqRYeYRiJby/nOHTI=","wrapped_cek":{"v":1,"nonce":"QZPVZntrLBXEPMqp9hT/sFolIzybrjuF","ct":"oSMScaL8yD9dm3WtpfW1oCkUxvTutVnN18Q/XENJh+VMZ7LzJX9K32Hd9n+p0aAr"},"cek_commit":"DBHmDIfPNSk+gyW4gH7wWed+FZAzR8E9lnvjTiDpt7o=","body":{"v":1,"nonce":"qVe5JV2C/6e74/RGT3Af97/yM1Ivip+S","ct":"are9RWFe7eoAOLiknj/GJd6C8WC3x5SHS7RMDxkqAHyMrYG4wJw84E+bE1n7ZX/ttkJ5hiQvT0rrl47jaB7AL6VmUNYShAsN/Z9kUWx1Lf4A0Sk/yhu818fSt7w7zr2OUgBDSUioSU39GVRFrywq/nNtPQszogwg4xw1UCConHPIs0bNJ0gp6GieDwLaYkhVmEOCCVZY194Gpyo4FBYKOLU3oVCuimaB2S823kL1zd2WhGnMH16Zpsyt+mJQFaUxWG6RHO/Tnzz04oKdQ/NDF2E6qDWYSsKIy5VMwKqys/rSoglUMa7/gXNxhvJ2LO3QBPdwRAHEQpJp8UnREAT5PBJ0Rnqu61/l+8bbPgAVbMg="}}"#;

// A locked record produced by the current implementation (from
// FROZEN_SEND_BLOB, contact "contact-kat", phrase "orange kettle drum",
// salt 0x33×16, KAT params) and frozen.
const FROZEN_LOCKED_RECORD: &str = r#"{"v":1,"local_id":"r3daXYlHjd5HXD4llHIWNg==","contact_id":"contact-kat","message_id":"C0+YVgpEBKPL4jFtc12dZw==","lock_commit":"TUTbRJf4XID6buYVMXzcCoNr41a4f80i4lfUUXoUmvQ=","body":{"v":1,"nonce":"3bunx2q/K2quCHIVv/DGtspDeVk+rwU8","ct":"Zr/Y05Y79zBK0G0r9lLirEha1lviO7atJX+UlKrqVXtAOrONn6ETU2VU8WflDFV8pSAh/491O6dbmZiZA7SMhVzos4BsHNl1hZwa2WxfJEE2buQoq5yM"},"created_at":1700000000}"#;

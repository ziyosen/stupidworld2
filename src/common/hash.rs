use sha2::{Digest, Sha256};

/// Trait untuk hash yang menghasilkan 32-byte output
trait Hasher32: Clone {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

/// Implementasi Hasher32 untuk Sha256
#[derive(Clone)]
struct Sha256Hash(Sha256);

impl Sha256Hash {
    fn new() -> Self {
        Self(Sha256::new())
    }
}

impl Hasher32 for Sha256Hash {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

/// Recursive HMAC-like hashing
#[derive(Clone)]
struct RecursiveHash<H: Hasher32 + Clone> {
    inner: H,
    outer: H,
    opad: [u8; 64],
}

impl<H: Hasher32 + Clone> RecursiveHash<H> {
    fn new(key: &[u8], base: H) -> Self {
        assert!(key.len() <= 64, "Key too long");

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];

        for i in 0..key.len() {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }

        let mut inner = base.clone();
        inner.update(&ipad);

        let mut outer = base;
        // opad disimpan, update dilakukan saat finalize

        Self {
            inner,
            outer,
            opad,
        }
    }
}

impl<H: Hasher32 + Clone> Hasher32 for RecursiveHash<H> {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        let inner_result = self.inner.finalize();
        self.outer.update(&self.opad);
        self.outer.update(&inner_result);
        self.outer.finalize()
    }
}

/// Key Derivation Function
pub fn kdf<H: Hasher32 + Clone>(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current: Box<dyn Hasher32> =
        Box::new(RecursiveHash::new(b"VMess AEAD KDF", H::clone(&H::clone(&Sha256Hash::new()))));

    for p in path {
        current = Box::new(RecursiveHash::new(p, current.finalize_hasher()));
    }

    current.update(key);
    current.finalize()
}

// Ekstensi trait untuk mendapatkan hasher baru dari output lama (tanpa Box)
trait FinalizeHasher: Hasher32 {
    fn finalize_hasher(&self) -> Self {
        self.clone()
    }
}

impl<T: Hasher32 + Clone> FinalizeHasher for T {}

/// Optional helper: md5(key1 + key2) untuk UUID
#[macro_export]
macro_rules! md5 {
    ($a:expr, $b:expr) => {{
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update($a);
        hasher.update($b);
        hasher.finalize()
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        use uuid::uuid;

        let uuid = uuid!("96850032-1b92-46e9-a4f2-b99631456894").as_bytes();
        let key = crate::md5!(uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");

        let result = kdf::<Sha256Hash>(&key, &[b"AES Auth ID Encryption"]);

        assert_eq!(
            &result[..16],
            &[117, 82, 144, 159, 147, 65, 74, 253, 91, 74, 70, 84, 114, 118, 203, 30]
        );
    }
}

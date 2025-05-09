use sha2::{Digest, Sha256};

struct RecursiveHash {
    inner: Sha256,
    outer: Sha256,
    ipad: [u8; 64],
    opad: [u8; 64],
}

impl RecursiveHash {
    fn new(key: &[u8]) -> Self {
        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];

        ipad[..key.len()].copy_from_slice(key);
        opad[..key.len()].copy_from_slice(key);

        for b in &mut ipad {
            *b ^= 0x36;
        }

        for b in &mut opad {
            *b ^= 0x5c;
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);
        let outer = Sha256::new();

        Self {
            inner,
            outer,
            ipad,
            opad,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(mut self) -> [u8; 32] {
        let inner_result = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_result);
        outer.finalize().into()
    }
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current = RecursiveHash::new(b"VMess AEAD KDF");

    for p in path {
        current = {
            let mut next = RecursiveHash::new(p);
            next.update(&current.finalize());
            next
        };
    }

    current.update(key);
    current.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::Md5;

    #[test]
    fn test_kdf() {
        let uuid = uuid::uuid!("96850032-1b92-46e9-a4f2-b99631456894").as_bytes();
        let key = crate::md5!(&uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");

        let res = kdf(&key, &[b"AES Auth ID Encryption"]);

        assert_eq!(
            res[..16],
            [117, 82, 144, 159, 147, 65, 74, 253, 91, 74, 70, 84, 114, 118, 203, 30]
        );
    }
}

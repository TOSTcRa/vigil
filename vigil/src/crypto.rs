use std::fs::File;
use std::io::Read;

// sha-256 constants - first 32 bits of the fractional parts of the cube roots of the first 64 primes
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// initial hash values - first 32 bits of the fractional parts of the square roots of the first 8 primes
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// sha-256 following fips 180-4
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();

    msg.push(0x80);

    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }

    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H_INIT;

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut res = [0u8; 32];
    for i in 0..8 {
        res[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    res
}

// returns sha-256 as lowercase hex string
pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&sha256(data))
}

// ---- hex encoding ----

const HEX_CHARS: &[u8] = b"0123456789abcdef";

// converts bytes to lowercase hex string
pub fn to_hex(bytes: &[u8]) -> String {
    let mut res = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        res.push(HEX_CHARS[(b >> 4) as usize] as char);
        res.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    res
}

// ---- random bytes from /dev/urandom ----

// fills buf with random bytes from /dev/urandom
pub fn random_bytes(buf: &mut [u8]) {
    let mut f = File::open("/dev/urandom").expect("failed to open /dev/urandom");
    f.read_exact(buf).expect("failed to read /dev/urandom");
}

fn random_bytes_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    random_bytes(&mut buf);
    buf
}

// ---- uuid v4 ----

// generates a random uuid v4 (rfc 4122)
pub fn uuid_v4() -> String {
    let mut bytes = random_bytes_array::<16>();

    // set version to 4 (bits 4-7 of byte 6)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // set variant to 10xx (bits 6-7 of byte 8)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_sha256_longer() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let hash = sha256_hex(data);
        assert_eq!(hash, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let hex = to_hex(&data);
        assert_eq!(hex, "deadbeef00ff");
    }

    #[test]
    fn test_uuid_v4_format() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[8], b'-');
        assert_eq!(id.as_bytes()[13], b'-');
        assert_eq!(id.as_bytes()[18], b'-');
        assert_eq!(id.as_bytes()[23], b'-');
        assert_eq!(id.as_bytes()[14], b'4');
        let variant = id.as_bytes()[19];
        assert!(variant == b'8' || variant == b'9' || variant == b'a' || variant == b'b');
    }

    #[test]
    fn test_uuid_v4_unique() {
        let a = uuid_v4();
        let b = uuid_v4();
        assert_ne!(a, b);
    }

    #[test]
    fn test_random_bytes() {
        let a = random_bytes_array::<32>();
        let b = random_bytes_array::<32>();
        assert_ne!(a, b);
    }
}

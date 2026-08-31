//! Digests for the toolchains the build downloads.
//!
//! Every archive that is fetched over the network is checked against a digest
//! that is part of the source tree, so that a build either uses the bytes this
//! repository was tested against or stops and says which ones it got instead.
//!
//! SHA-256 is written out here rather than taken from a crate because xtask is
//! meant to pull in as little as possible; the algorithm is FIPS 180-4 and the
//! tests below run the vectors published with it.

use std::{
    fmt::Display,
    io::{self, Read},
    path::Path,
};

/// The digest of every archive the build is allowed to download, in the format
/// `sha256sum` writes, so that the same file checks out with
/// `sha256sum --check`.
const PINNED: &str = include_str!("../toolchain.sha256");

/// Reads the pinned digest of `artifact`, named the way the release publishes
/// it.
///
/// Input:  `"binaryen-version_119-x86_64-linux.tar.gz"`
/// Output: the 64 hex characters that archive has to hash to
pub fn pinned(artifact: &str) -> Option<&'static str> {
    PINNED.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        // `sha256sum` separates the two with two spaces, the second of which
        // says the file was read as binary.
        let (digest, name) = line.split_once("  ")?;
        (name.trim() == artifact).then_some(digest)
    })
}

/// Checks a downloaded archive against the digest pinned for it.
pub fn verify(path: impl AsRef<Path>, artifact: &str) -> Result<(), ChecksumError> {
    let actual = of_file(path.as_ref()).map_err(ChecksumError::IO)?;

    match pinned(artifact) {
        Some(expected) if expected.eq_ignore_ascii_case(&actual) => Ok(()),
        Some(expected) => Err(ChecksumError::Mismatch {
            artifact: artifact.to_string(),
            expected: expected.to_string(),
            actual,
        }),
        None => Err(ChecksumError::Unpinned {
            artifact: artifact.to_string(),
            actual,
        }),
    }
}

/// The SHA-256 of a file, as lowercase hex.
pub fn of_file(path: impl AsRef<Path>) -> io::Result<String> {
    let mut file = io::BufReader::new(std::fs::File::open(path)?);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finish()))
}

#[derive(Debug)]
pub enum ChecksumError {
    /// The archive is not the one that was pinned
    Mismatch {
        artifact: String,
        expected: String,
        actual: String,
    },
    /// The archive is one this build has never seen
    Unpinned {
        artifact: String,
        actual: String,
    },
    IO(io::Error),
}

impl Display for ChecksumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChecksumError::Mismatch {
                artifact,
                expected,
                actual,
            } => write!(
                f,
                "'{artifact}' is not the archive this build pins:\n\
                 \texpected {expected}\n\
                 \tgot      {actual}\n\
                 the downloaded file has been removed"
            ),
            ChecksumError::Unpinned { artifact, actual } => write!(
                f,
                "no digest is pinned for '{artifact}'; after checking where it \
                 came from, add\n\n\t{actual}  {artifact}\n\nto \
                 xtask/toolchain.sha256, or set XTASK_ALLOW_UNPINNED_DOWNLOADS=1 \
                 to build without this check"
            ),
            ChecksumError::IO(io) => write!(f, "cannot read the downloaded file: {io}"),
        }
    }
}

impl std::error::Error for ChecksumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IO(source) => Some(source),
            _ => None,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut result, byte| {
        result.push_str(&format!("{byte:02x}"));
        result
    })
}

/// The first 32 bits of the fractional parts of the cube roots of the first 64
/// primes, as FIPS 180-4 defines them.
#[rustfmt::skip]
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The first 32 bits of the fractional parts of the square roots of the first
/// eight primes.
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLOCK: usize = 64;

/// SHA-256 as FIPS 180-4 defines it.
struct Sha256 {
    state: [u32; 8],
    /// Bytes waiting for the block they belong to to be filled
    pending: [u8; BLOCK],
    pending_len: usize,
    /// The length of everything fed in so far, which the padding carries
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            pending: [0; BLOCK],
            pending_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.total_len += bytes.len() as u64;

        if self.pending_len > 0 {
            let room = BLOCK - self.pending_len;
            let taken = room.min(bytes.len());
            self.pending[self.pending_len..self.pending_len + taken]
                .copy_from_slice(&bytes[..taken]);
            self.pending_len += taken;
            bytes = &bytes[taken..];

            if self.pending_len < BLOCK {
                return;
            }
            let block = self.pending;
            self.compress(&block);
            self.pending_len = 0;
        }

        let (blocks, rest) = bytes.as_chunks::<BLOCK>();
        for block in blocks {
            self.compress(block);
        }

        self.pending[..rest.len()].copy_from_slice(rest);
        self.pending_len = rest.len();
    }

    fn finish(mut self) -> [u8; 32] {
        // A one bit, then zeroes, then the length in bits as a 64 bit big
        // endian number, filling the last block exactly.
        let bit_len = self.total_len * 8;
        self.update(&[0x80]);
        while self.pending_len != BLOCK - 8 {
            self.update(&[0x00]);
        }
        // The padding itself must not count towards the length.
        self.update(&bit_len.to_be_bytes());

        let mut digest = [0u8; 32];
        let (words, _) = digest.as_chunks_mut::<4>();
        for (word, slot) in self.state.iter().zip(words) {
            *slot = word.to_be_bytes();
        }
        digest
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut schedule = [0u32; 64];
        let (words, _) = block.as_chunks::<4>();
        for (slot, bytes) in schedule.iter_mut().zip(words) {
            *slot = u32::from_be_bytes(*bytes);
        }
        for i in 16..64 {
            let s0 = schedule[i - 15].rotate_right(7)
                ^ schedule[i - 15].rotate_right(18)
                ^ (schedule[i - 15] >> 3);
            let s1 = schedule[i - 2].rotate_right(17)
                ^ schedule[i - 2].rotate_right(19)
                ^ (schedule[i - 2] >> 10);
            schedule[i] = schedule[i - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(ROUND_CONSTANTS[i])
                .wrapping_add(schedule[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{hex, pinned, verify, ChecksumError, Sha256, PINNED};
    use crate::test_support::TempFile;

    fn sha256(bytes: &[u8]) -> String {
        let mut digest = Sha256::new();
        digest.update(bytes);
        hex(&digest.finish())
    }

    /// The examples published with FIPS 180-4: nothing, less than one block,
    /// and more than one block.
    #[test]
    fn the_published_vectors_hash_to_their_published_digests() {
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256(&[b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// The archives are hashed in whatever pieces the reader hands over, so a
    /// digest must not depend on where those pieces end.
    #[test]
    fn the_digest_does_not_depend_on_how_the_input_is_split() {
        let message: Vec<u8> = (0..1000u32).map(|it| it as u8).collect();
        let whole = sha256(&message);

        for chunk in [1, 7, 63, 64, 65, 128, 999] {
            let mut digest = Sha256::new();
            for piece in message.chunks(chunk) {
                digest.update(piece);
            }
            assert_eq!(hex(&digest.finish()), whole, "in pieces of {chunk}");
        }
    }

    /// A block that is filled exactly needs a whole block of padding after it,
    /// which is where a hand written implementation goes wrong.
    #[test]
    fn a_message_that_fills_its_last_block_is_padded_into_another() {
        for length in [55, 56, 57, 63, 64, 65, 119, 120, 128] {
            let message = vec![b'x'; length];
            let mut digest = Sha256::new();
            digest.update(&message);
            let in_one_go = hex(&digest.finish());

            let mut digest = Sha256::new();
            for byte in &message {
                digest.update(&[*byte]);
            }
            assert_eq!(hex(&digest.finish()), in_one_go, "{length} bytes");
        }
    }

    #[test]
    fn a_file_is_hashed_by_its_contents() {
        let file = TempFile::holding("abc");
        assert_eq!(
            super::of_file(file.path()).expect("the file written above"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Every line has to be readable as `sha256sum` output, or the digest of a
    /// tool would silently go missing.
    #[test]
    fn the_pinned_file_is_a_list_of_digests_and_names() {
        let entries: Vec<(&str, &str)> = PINNED
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                line.split_once("  ")
                    .unwrap_or_else(|| panic!("two spaces between digest and name: {line}"))
            })
            .collect();

        assert!(!entries.is_empty(), "the digests are missing");
        for (digest, name) in &entries {
            assert_eq!(digest.len(), 64, "{name} has a digest of the wrong length");
            assert!(
                digest.chars().all(|it| it.is_ascii_hexdigit()),
                "{name} has a digest that is not hex"
            );
        }

        let mut names: Vec<&str> = entries.iter().map(|(_, name)| *name).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(unique, names.len(), "an archive is pinned twice");
    }

    #[test]
    fn an_archive_that_is_not_pinned_has_no_digest() {
        assert!(pinned("binaryen-version_1-x86_64-linux.tar.gz").is_none());
    }

    /// The digest of a pinned archive is what says the download is the one the
    /// build was tested against, so a file that is not it has to be refused.
    #[test]
    fn a_file_that_is_not_the_pinned_archive_is_reported() {
        let file = TempFile::holding("abc");
        let artifact = PINNED
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .find_map(|line| line.split_once("  ").map(|(_, name)| name))
            .expect("at least one pinned archive");

        let error = verify(file.path(), artifact).expect_err("that is not the archive");
        assert!(
            matches!(error, ChecksumError::Mismatch { .. }),
            "unexpected error: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "the error should carry the digest that was found: {error}"
        );
    }

    #[test]
    fn a_file_nothing_is_pinned_for_says_what_to_add() {
        let file = TempFile::holding("abc");

        let error = verify(file.path(), "something-nobody-pinned.tar.gz")
            .expect_err("nothing is pinned for it");

        assert!(
            matches!(error, ChecksumError::Unpinned { .. }),
            "unexpected error: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  \
                 something-nobody-pinned.tar.gz"
            ),
            "the error should spell out the line to add: {message}"
        );
    }
}

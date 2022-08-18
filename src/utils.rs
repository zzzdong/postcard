use std::{io::Read, path::Path};

// Noise protocol params, see: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
// Use `KK` to enable bidirectional identity verification
pub static PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

pub fn load_identify(path: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path.as_ref())?;
    let mut identity = vec![];
    file.read_to_end(&mut identity)?;

    Ok(identity)
}

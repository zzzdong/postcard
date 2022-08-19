// Noise protocol params, see: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
// Use `KK` to enable bidirectional identity verification
pub static PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

pub fn load_identify(key_str: &str) -> anyhow::Result<Vec<u8>> {
    let identity = base64::decode(key_str)?;

    Ok(identity)
}

fn main() {
    // Generate a private / public key pair
    let key_pair = snowstorm::Builder::new(postcard::utils::PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    std::fs::write("keys/private_key.bin", key_pair.private).unwrap();
    std::fs::write("keys/public_key.bin", key_pair.public).unwrap();
}

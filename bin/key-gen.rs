fn main() {
    // Generate a private / public key pair
    let key_pair = snowstorm::Builder::new(postcard::utils::PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    println!("private key: {}", base64::encode(key_pair.private));
    println!("public  key: {}", base64::encode(key_pair.public));
}

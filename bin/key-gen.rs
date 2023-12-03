use base64::{engine::general_purpose, Engine as _};

fn main() {
    // Generate a private / public key pair
    let key_pair = snowstorm::Builder::new(postcard::secure_stream::PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    println!(
        "private key: {}",
        general_purpose::STANDARD.encode(key_pair.private)
    );
    println!(
        "public  key: {}",
        general_purpose::STANDARD.encode(key_pair.public)
    );
}

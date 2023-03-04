use base64::prelude::{Engine, BASE64_STANDARD};

fn main() {
    // Generate a private / public key pair
    let key_pair = snowstorm::Builder::new(postcard::secure_stream::PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    println!("private key: {}", BASE64_STANDARD.encode(key_pair.private));
    println!("public  key: {}", BASE64_STANDARD.encode(key_pair.public));
}

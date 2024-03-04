pub mod auth {
    include!("./auth.rs");
}

use crate::auth::*;
use auth::auth_client::AuthClient;
use chaum_pedersen_zkp::constants;
use chaum_pedersen_zkp::constants::ALPHA;
use chaum_pedersen_zkp::ZKP;
use num_bigint::BigUint;
use prost::bytes::buf;
use std::io::stdin;

#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let addr = "127.0.0.1:50051".to_string();
    let client = AuthClient::connect(addr.clone())
        .await
        .expect(&format!("could not connect to the server on {:?}", addr));
    println!("✅Client Connected to the server");
    println!("Provide username: ");
    stdin()
        .read_line(&mut buf)
        .expect("could not get the username from stdin");
    let username = buf.trim().to_string();
    println!("Provide password: ");
    stdin()
        .read_line(&mut buf)
        .expect("could not get password from the stdin");
    let password = buf.trim().as_bytes();
    let y1 = ZKP::exponentiate(
        &BigUint::from_bytes_be(&hex::decode(constants::ALPHA).unwrap()),
        &BigUint::from_bytes_be(password),
        &BigUint::from_bytes_be(&hex::decode(constants::P).unwrap()),
    );

    // let response = RegisterRequest{
    //     user: username,
    //     y1,
    //     y2
    // }
}

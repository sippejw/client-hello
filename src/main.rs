#[macro_use]
extern crate enum_primitive;

mod ch;
use std::env;

use ch::{ClientHello, TlsRecordType};
use hex::decode;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("./client_hello <client hello byte string>");
        return
    }
    let a = decode(&args[1]).unwrap();
    let client_hello = ClientHello::from_try(&a, Some(TlsRecordType::Handshake), ch::TlsVersion::TLS12).unwrap();
    let fingerprint = client_hello.get_fingerprint();
    println!("Client Hello: {{ id: {} {}}}", fingerprint, client_hello);
}

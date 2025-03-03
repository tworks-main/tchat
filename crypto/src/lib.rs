use crypto_bigint::subtle::{ConstantTimeEq, Choice};
use crypto_bigint::{rand_core::OsRng, Random};
use crypto_bigint::{ArrayEncoding, Encoding, Limb, U256};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
pub use curve25519_dalek::scalar::Scalar;
use hex::FromHex;
use sha2::{Digest, Sha256};
use itertools::Itertools;
use std::str;

#[derive(Clone)]
pub struct Keys {
    pub seed: String,
    pub public: String
}

impl Keys {
    pub fn empty() -> Self {
        Self {
            seed: String::new(),
            public: String::new()
        }
    }
    pub fn from_scalar(scalar: &Scalar) -> Self {
        Self {
           seed: scalar_to_mnemonic(scalar),
           public: scalar_to_public_hex(scalar)
        }
    }
    pub fn from_mnemonic(mnemonic: String) -> Self {
        let scalar = mnemonic_to_scalar(&mnemonic);
        Self {
           seed: mnemonic,
           public: scalar_to_public_hex(&scalar)
        }
    }
}

pub fn generate_secret() -> Scalar {
    let mut rng = OsRng;
    Scalar::random(&mut rng)
}

pub fn scalar_to_hex(secret: &Scalar) -> String {
    hex::encode(secret.to_bytes())
}

pub fn secret_hex_to_scalar(secret: &str) -> Scalar {
    let bytes = <[u8; 32]>::from_hex(secret).unwrap();
    Scalar::from_bytes_mod_order(bytes)
}

fn secret_to_public(secret: &Scalar) -> CompressedEdwardsY {
    EdwardsPoint::mul_base(secret).compress()
}

fn compressededwardsy_to_hex(y: CompressedEdwardsY) -> String {
    hex::encode(y.to_bytes())
}

pub fn scalar_to_public_hex(secret: &Scalar) -> String {
    let public: CompressedEdwardsY = secret_to_public(secret);
    compressededwardsy_to_hex(public)
}

pub fn scalar_to_mnemonic(secret: &Scalar) -> String {
    let bytes = secret.to_bytes();
    mnemonic::to_string(bytes)
}

pub fn mnemonic_to_scalar(mnemonic: &str) -> Scalar {
    let mut dest: Vec<u8> = Vec::new();
    mnemonic::decode(mnemonic, &mut dest).unwrap();
    let bytes: [u8; 32] = dest.try_into().unwrap();
    Scalar::from_bytes_mod_order(bytes)
}

pub fn encrypt_secret(secret: &Scalar, passwd: &str) -> [String; 2] {
    let secret = U256::from_be_bytes(secret.to_bytes());
    let offset_hash = U256::from_be_byte_array(Sha256::digest(format!("offset_hash{}",passwd)));
    let encrypt_secret = U256::add_mod_special(&secret, &offset_hash, Limb::ZERO);
    let passwd_hash = hex::encode(Sha256::digest(format!("passwd_hash{}", passwd)));
    [encrypt_secret.to_string(), passwd_hash]
}

pub fn decrypt_secret(encrypt_secret: &str, passwd: &str) -> Scalar {
    let offset_hash = U256::from_be_byte_array(Sha256::digest(format!("offset_hash{}", passwd)));
    let encrypt_secret = U256::from_be_hex(encrypt_secret);
    let decrypt_secret = U256::sub_mod_special(&encrypt_secret, &offset_hash, Limb::ZERO);
    Scalar::from_bytes_mod_order(decrypt_secret.to_be_bytes())
}

pub fn check_passwd(passwd: &str, passwd_hash: &str) -> bool {
    let hashed_passwd = U256::from_be_byte_array(Sha256::digest(format!("passwd_hash{}", passwd)));
    let passwd_hash = U256::from_be_hex(passwd_hash);   
    <bool>::from(passwd_hash.ct_eq(&hashed_passwd))
}

pub fn check_mnemonic(mnemonic: &str) -> bool {
    let mut dest: Vec<u8> = Vec::new();
    match mnemonic::decode(mnemonic, &mut dest) {
        Ok(size) => size == 32,
        Err(_) => false
    }
}

pub fn check_public(public: &str) -> bool {
    match &<[u8; 32]>::from_hex(public) {
        Ok(bytes) => {
            let compressed = CompressedEdwardsY::from_slice(bytes).unwrap();
            CompressedEdwardsY::decompress(&compressed).is_some()
        },
        Err(_) => false
    }
}
//message encryption-decryption
pub fn shared_secret(secret: &Scalar, public: &str) -> [u8; 32] {
    let public: &[u8] = &<[u8; 32]>::from_hex(public).unwrap();
    let public: CompressedEdwardsY = CompressedEdwardsY::from_slice(public).unwrap();
    (CompressedEdwardsY::decompress(&public).unwrap() * secret).compress().to_bytes()
}

fn split_msg(string: &str) -> Vec<&[u8]> {
    let vec: Vec<&[u8]> = string.as_bytes().chunks(32).collect();
    vec
}

fn pad_spaces(array: &[u8]) -> [u8; 32] {
    let mut b = [32; 32];
    b[..array.len()].copy_from_slice(array);
    b
}

fn lower_length(array: &[u8]) -> U256 {
    U256::from_be_bytes(pad_spaces(array))
}

fn to_u256(vec: Vec<&[u8]>) -> Vec<U256> {
    let mut new_vec: Vec<&[u8]> = vec.clone();
    let last_element: &[u8] = new_vec.pop().unwrap();
    if last_element.len() == 32 {
        vec.iter().map(|x| U256::from_be_slice(x)).collect()
    } else {
        let mut new_vec: Vec<U256> = new_vec.iter().map(|x| U256::from_be_slice(x)).collect();
        let last_element: U256 = lower_length(last_element);
        new_vec.push(last_element);
        new_vec
    }
}

fn hash_crypt(rand: [u8; 32], shared_secret: [u8; 32]) -> U256 {
    let mut rand: Vec<u8> = rand.into();
    let mut shared_secret: Vec<u8> = shared_secret.into();
    rand.append(&mut shared_secret);
    U256::from_be_byte_array(Sha256::digest(rand))
}

pub fn big_rand() -> String {
    let n = U256::random(&mut OsRng);
    U256::to_string(&n)
}

pub fn encrypt(msg: &str, shared_secret: [u8; 32]) -> String {
    let mut u256_vec: Vec<U256> = to_u256(split_msg(msg));
    let rand: String = big_rand();
    let rand_bytes = <[u8; 32]>::from_hex(rand.clone()).unwrap();
    let hashed_rand_and_shared_secret: U256 = hash_crypt(rand_bytes, shared_secret);
    u256_vec = u256_vec
        .iter()
        .map(|x| U256::add_mod_special(x, &hashed_rand_and_shared_secret, Limb::ZERO))
        .collect();
    let mut hex_vec: Vec<String> = u256_vec
        .iter()
        .map(U256::to_string)
        .collect();
    hex_vec.push(rand);
    let hex_string: String = hex_vec.concat();
    hex_string
}

pub fn decrypt(msg: &str, shared_secret: [u8; 32]) -> String {
    let mut hex_vec: Vec<String> = msg.chars().chunks(64).into_iter().map(|chunk| chunk.collect::<String>()).collect::<Vec<_>>();
    let rand = hex_vec.pop().unwrap();
    let rand = <[u8; 32]>::from_hex(rand).unwrap();
    let mut u256_vec: Vec<U256> = hex_vec.iter().map(|x| U256::from_be_hex(x)).collect();
    let hashed_rand_and_shared_secret: U256 = hash_crypt(rand, shared_secret);
    u256_vec = u256_vec
        .iter()
        .map(|x| U256::sub_mod_special(x, &hashed_rand_and_shared_secret, Limb::ZERO))
        .collect();
    let bytes_vec: Vec<[u8; 32]> = u256_vec.iter().map(U256::to_be_bytes).collect();
    let string_vec: Vec<String> = bytes_vec
        .iter()
        .map(|x| String::from_utf8(x.to_vec()).unwrap())
        .collect();
    let string: String = string_vec.concat();
    string
}

//signature
fn hash(bytes_value: Vec<u8>) -> [u8; 32] {
    Sha256::digest(bytes_value).into()
}

fn concat_alpha(array: [u8; 32], string: &str) -> Vec<u8> {
    let mut array_vec: Vec<u8> = array.into();
    let string: [u8; 32] = FromHex::from_hex(string).unwrap();
    let mut string_vec: Vec<u8> = string.into();
    array_vec.append(&mut string_vec);
    array_vec
}

fn concat_challenge(array1: [u8; 32], array2: [u8; 32], string: &str) -> Vec<u8> {
    let mut array1_vec: Vec<u8> = array1.into();
    let mut array2_vec: Vec<u8> = array2.into();
    let string: [u8; 32] = FromHex::from_hex(string).unwrap();
    let mut string_vec: Vec<u8> = string.into();
    array1_vec.append(&mut array2_vec);
    array1_vec.append(&mut string_vec);
    array1_vec
}

pub fn sign(secret: &Scalar, public: &str, message: &str) -> String {
    let secret_array: [u8; 32] = secret.to_bytes();
    let secret_vec: Vec<u8> = secret_array.into();
    let hash_secret: [u8; 32] = hash(secret_vec);
    let alpha: [u8; 32] = hash(concat_alpha(hash_secret, message));
    let alpha: Scalar = Scalar::from_bytes_mod_order(alpha);
    let alpha_generator: [u8; 32] = EdwardsPoint::mul_base(&alpha).compress().to_bytes();
    let alpha_generator_hex: String = hex::encode(alpha_generator);
    let public: [u8; 32] = FromHex::from_hex(public).unwrap();
    let challenge: [u8; 32] = hash(concat_challenge(alpha_generator, public, message));
    let challenge_scalar: Scalar = Scalar::from_bytes_mod_order(challenge);
    let response: Scalar = alpha + challenge_scalar * secret;
    let response: [u8; 32] = response.to_bytes();
    let response_hex: String = hex::encode(response);
    let signature = [alpha_generator_hex, response_hex];
    signature.concat()
}

pub fn verify(signature: &str, public: &str, message: &str) -> bool {
    let (alpha_generator, response) = signature.split_at(64);
    let hex_array = [alpha_generator, response]; 
    let alpha_generator_compressed: &str = hex_array[0];
    let alpha_generator_compressed_bytes: [u8; 32] = <[u8; 32]>::from_hex(alpha_generator_compressed).expect("Decoding failed");
    let alpha_generator: &[u8] = &<[u8; 32]>::from_hex(alpha_generator_compressed).expect("Decoding failed");
    let alpha_generator: CompressedEdwardsY = CompressedEdwardsY::from_slice(alpha_generator).unwrap();
    let alpha_generator: EdwardsPoint = CompressedEdwardsY::decompress(&alpha_generator).unwrap();
    let response: &str = response;
    let response: [u8; 32] = <[u8; 32]>::from_hex(response).expect("Decoding failed");
    let response: Scalar = Scalar::from_bytes_mod_order(response);
    let public: &[u8] = &<[u8; 32]>::from_hex(public).expect("Decoding failed");
    let public: CompressedEdwardsY = CompressedEdwardsY::from_slice(public).unwrap();
    let public_bytes: [u8; 32] = public.to_bytes();
    let challenge: [u8; 32] = hash(concat_challenge(alpha_generator_compressed_bytes, public_bytes, message));
    let challenge: Scalar = Scalar::from_bytes_mod_order(challenge);
    let left_side: EdwardsPoint = EdwardsPoint::mul_base(&response);
    let right_side: EdwardsPoint = alpha_generator + CompressedEdwardsY::decompress(&public).unwrap() * challenge;
    let verification: Choice = EdwardsPoint::ct_eq(&left_side, &right_side);
    <bool>::from(verification)
}

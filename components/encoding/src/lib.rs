use base64::{engine::general_purpose::STANDARD, Engine};
use warg_crypto::signing::PublicKey;
use p256;

struct Component;

impl bindings::Encoding for Component {
    fn encode_base64(content: Vec<u8>) -> String {
        STANDARD.encode(content)
    }

    fn decode_base64(encoded: String) -> Result<Vec<u8>, ()> {
        match STANDARD.decode(encoded) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(()),
        }
    }

    fn key_id(public_key: String) -> Result<String, ()> {
        let public_key = match public_key.parse::<PublicKey>() {
            Ok(public_key) => public_key,
            Err(_) => return Err(()),
        };
        Ok(public_key.fingerprint().to_string())
    }

    fn signature_from_fixed_width_to_der(src: Vec<u8>) -> Result<Vec<u8>, ()> {
        let signature = match p256::ecdsa::Signature::from_slice(&src) {
            Ok(signature) => signature,
            Err(_) => return Err(()),
        };
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn signature_from_der_to_fixed_width(src: Vec<u8>) -> Result<Vec<u8>, ()> {
        let signature = match p256::ecdsa::Signature::from_der(&src) {
            Ok(signature) => signature,
            Err(_) => return Err(()),
        };
        Ok(signature.to_vec())
    }
}

bindings::export!(Component);

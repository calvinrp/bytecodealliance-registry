use base64::{engine::general_purpose::STANDARD, Engine};

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
}

bindings::export!(Component);

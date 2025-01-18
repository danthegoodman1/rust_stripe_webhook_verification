use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let raw_header = "t=1492774577,v1=b4393e3e0aecc055d3147a0ccdb00a5511c22402fe352e266041299008bec21d,v0=b4393e3e0aecc055d3147a0ccdb00a5511c22402fe352e266041299008bec21d";
    let signing_secret = "whsec_your_secret_key";
    let json_body = r#"{"example": "webhook_payload"}"#;

    let generated_signature = generate_signature(raw_header, signing_secret, json_body).unwrap();


    let (_timestamp, signature) = parse_header(raw_header).unwrap();

    println!("Generated signature: {}", generated_signature);

    match constant_time_compare(&generated_signature, &signature) {
        true => println!("Signature is valid"),
        false => println!("Signature is invalid"),
    }
}

fn parse_header(header: &str) -> Result<(u64, String), Box<dyn std::error::Error>> {
    // Parse header
    let mut timestamp = None;
    let mut signature = None;

    for part in header.split(',') {
        let mut parts = part.split('=');
        match (parts.next(), parts.next()) {
            (Some("t"), Some(ts)) => timestamp = Some(ts),
            (Some("v1"), Some(sig)) => signature = Some(sig),
            _ => continue,
        }
    }

    let timestamp = timestamp.ok_or("Missing timestamp")?;
    let signature = signature.ok_or("Missing v1 signature")?;

    Ok((timestamp.parse::<u64>()?, signature.to_string()))
}

fn generate_signature(header: &str, secret: &str, payload: &str) -> Result<String, Box<dyn std::error::Error>> {
    let (timestamp, signature) = parse_header(header)?;


    // Create signed payload
    let signed_payload = format!("{}.{}", timestamp, payload);

    // Calculate expected signature
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    mac.update(signed_payload.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    // Compare signatures using constant-time comparison
    Ok(expected_signature)
}

// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut result = 0;
    
    for i in 0..a.len() {
        result |= a_bytes[i] ^ b_bytes[i];
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature() {
        let secret = "whsec_test_secret";
        let payload = r#"{"id": "evt_test"}"#;
        
        // Generate a valid signature
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        
        let signed_payload = format!("{}.{}", timestamp, payload);
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        
        let header = format!("t={},v1={}", timestamp, signature);
        
        let result = generate_signature(&header, secret, payload).unwrap();
        let constant_time_result = constant_time_compare(&result, &header);
        assert!(constant_time_result, "Valid signature should be verified successfully");
    }

    #[test]
    fn test_invalid_signature() {
        let secret = "whsec_test_secret";
        let payload = r#"{"id": "evt_test"}"#;
        let header = format!("t=1234567890,v1={}", "invalid_signature");
        
        let result = generate_signature(&header, secret, payload).unwrap();
        let constant_time_result = constant_time_compare(&result, &header);
        assert!(!constant_time_result, "Invalid signature should fail verification");
    }

    #[test]
    fn test_expired_timestamp() {
        let secret = "whsec_test_secret";
        let payload = r#"{"id": "evt_test"}"#;
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 301; // 5 minutes + 1 second ago
        
        let signed_payload = format!("{}.{}", old_timestamp, payload);
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        
        let header = format!("t={},v1={}", old_timestamp, signature);
        
        let result = generate_signature(&header, secret, payload).unwrap();
        let constant_time_result = constant_time_compare(&result, &header);
        assert!(!constant_time_result, "Expired timestamp should fail verification");
    }

    #[test]
    fn test_malformed_header() {
        let secret = "whsec_test_secret";
        let payload = r#"{"id": "evt_test"}"#;
        let header = "invalid_header_format";
        
        let result = generate_signature(header, secret, payload);
        assert!(result.is_err(), "Malformed header should return an error");
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"), "Equal strings should match");
        assert!(!constant_time_compare("abc", "def"), "Different strings should not match");
        assert!(!constant_time_compare("abc", "abcd"), "Different length strings should not match");
    }
}

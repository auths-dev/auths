use anyhow::{Context, Result, anyhow};

/// Parse witness key arguments ("did:key:z6Mk...:abcd1234...") into (DID, pk_bytes) tuples.
pub fn parse_witness_keys(keys: &[String]) -> Result<Vec<(String, Vec<u8>)>> {
    keys.iter()
        .map(|s| {
            // Find the last ':' to split DID from hex key
            let last_colon = s
                .rfind(':')
                .ok_or_else(|| anyhow!("Invalid witness key format '{}': expected DID:hex", s))?;
            let did = &s[..last_colon];
            let pk_hex = &s[last_colon + 1..];
            let pk_bytes = hex::decode(pk_hex)
                .with_context(|| format!("Invalid hex in witness key for '{}'", did))?;
            Ok((did.to_string(), pk_bytes))
        })
        .collect()
}

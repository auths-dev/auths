use anyhow::{Context, Result, anyhow};
use auths_verifier::core::Attestation;
use jsonschema;
use serde_json::{Value, to_vec_pretty};

/// An encoder that validates an Attestation's optional `payload` field
/// against a provided JSON schema before serializing the entire Attestation.
#[derive(Clone, Debug)]
pub struct JsonSchemaValidatingEncoder {
    schema_value: Value,
}

impl JsonSchemaValidatingEncoder {
    /// Creates a new validating encoder which will use the provided schema.
    pub fn new(schema_value: Value) -> Self {
        Self { schema_value }
    }

    /// Validates the `att.payload` against the stored schema (if payload exists)
    /// and then serializes the entire `att` struct to pretty JSON bytes.
    ///
    /// Returns `Err` if schema validation fails for an existing payload, or if
    /// final JSON serialization fails.
    pub fn encode(&self, att: &Attestation) -> Result<Vec<u8>> {
        // Validate ONLY the payload field if it is present
        if let Some(payload_value) = &att.payload {
            // Perform validation using the jsonschema crate
            if !jsonschema::is_valid(&self.schema_value, payload_value) {
                // If invalid, try validating again to get detailed errors
                let error_details = match jsonschema::validate(&self.schema_value, payload_value) {
                    Ok(_) => "Unknown validation error".to_string(),
                    Err(validation_error) => {
                        format!(
                            "Path '/payload{}': {:?}",
                            validation_error.instance_path(),
                            validation_error.kind()
                        ) // Adjust path display
                    }
                };
                // Return an error indicating schema failure
                return Err(anyhow!(
                    "Schema validation failed for payload: {}",
                    error_details
                ));
            }
            // If validation passes (or if there was no payload), proceed below
        }

        // Serialize the original Attestation struct if validation passed or was skipped
        to_vec_pretty(att).context("Failed to serialize validated attestation to JSON")
    }
}

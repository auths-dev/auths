use crate::error::StorageError;
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
    pub fn encode(&self, att: &Attestation) -> Result<Vec<u8>, StorageError> {
        if let Some(payload_value) = &att.payload {
            if !jsonschema::is_valid(&self.schema_value, payload_value) {
                let error_details = match jsonschema::validate(&self.schema_value, payload_value) {
                    Ok(_) => "Unknown validation error".to_string(),
                    Err(validation_error) => {
                        format!(
                            "Path '/payload{}': {:?}",
                            validation_error.instance_path(),
                            validation_error.kind()
                        )
                    }
                };
                return Err(StorageError::SchemaValidation(error_details));
            }
        }

        Ok(to_vec_pretty(att)?)
    }
}

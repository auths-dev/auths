use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;

use crate::error::TransparencyError;
use crate::store::TileStore;

const CACHE_IMMUTABLE: &str = "immutable, max-age=31536000";
const CACHE_SHORT: &str = "public, max-age=10";

/// S3-compatible tile store for transparency log persistence.
///
/// Stores tiles and checkpoints as objects in an S3 bucket (including
/// Tigris-compatible endpoints). Cache-Control headers are applied per
/// the C2SP tlog-tiles spec:
///
/// - Full tiles and entry bundles: `immutable, max-age=31536000`
/// - Partial tiles: `public, max-age=10`
/// - Checkpoint: `public, max-age=10`
///
/// Full tiles (paths without `.p/`) are write-once: if the object
/// already exists, subsequent writes are silently skipped. Partial
/// tiles and the checkpoint are always overwritten.
///
/// Args:
/// * `client` — An `aws_sdk_s3::Client` configured for the target endpoint.
/// * `bucket` — The S3 bucket name.
/// * `prefix` — An optional key prefix prepended to all object keys.
///
/// Usage:
/// ```ignore
/// let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
/// let client = aws_sdk_s3::Client::new(&config);
/// let store = S3TileStore::new(client, "my-tlog-bucket".into(), Some("v1/".into()));
/// store.write_tile("tile/0/000", &data).await?;
/// ```
pub struct S3TileStore {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3TileStore {
    /// Creates a new S3 tile store.
    ///
    /// Args:
    /// * `client` — Pre-configured S3 client (handles region, endpoint, credentials).
    /// * `bucket` — Target bucket name.
    /// * `prefix` — Optional key prefix (e.g., `"v1/"`). Pass `None` for no prefix.
    ///
    /// Usage:
    /// ```ignore
    /// let store = S3TileStore::new(client, "tlog-bucket".into(), None);
    /// ```
    pub fn new(client: Client, bucket: String, prefix: Option<String>) -> Self {
        Self {
            client,
            bucket,
            prefix: prefix.unwrap_or_default(),
        }
    }

    fn object_key(&self, path: &str) -> String {
        format!("{}{}", self.prefix, path)
    }

    async fn object_exists(&self, key: &str) -> Result<bool, TransparencyError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_not_found() {
                    Ok(false)
                } else {
                    Err(TransparencyError::StoreError(service_err.to_string()))
                }
            }
        }
    }

    async fn put_object(
        &self,
        key: &str,
        data: &[u8],
        cache_control: &str,
    ) -> Result<(), TransparencyError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data.to_vec()))
            .cache_control(cache_control)
            .content_type("application/octet-stream")
            .send()
            .await
            .map_err(|e| TransparencyError::StoreError(e.into_service_error().to_string()))?;
        Ok(())
    }

    async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>, TransparencyError> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let bytes = output
                    .body
                    .collect()
                    .await
                    .map_err(|e| TransparencyError::StoreError(e.to_string()))?;
                Ok(Some(bytes.to_vec()))
            }
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_no_such_key() {
                    Ok(None)
                } else {
                    Err(TransparencyError::StoreError(service_err.to_string()))
                }
            }
        }
    }
}

fn is_partial_tile(path: &str) -> bool {
    path.contains(".p/")
}

fn cache_control_for_tile(path: &str) -> &'static str {
    if is_partial_tile(path) {
        CACHE_SHORT
    } else {
        CACHE_IMMUTABLE
    }
}

#[async_trait::async_trait]
impl TileStore for S3TileStore {
    async fn read_tile(&self, path: &str) -> Result<Vec<u8>, TransparencyError> {
        let key = self.object_key(path);
        self.get_object(&key)
            .await?
            .ok_or_else(|| TransparencyError::StoreError(format!("tile not found: {path}")))
    }

    async fn write_tile(&self, path: &str, data: &[u8]) -> Result<(), TransparencyError> {
        let key = self.object_key(path);

        if !is_partial_tile(path) && self.object_exists(&key).await? {
            return Ok(());
        }

        self.put_object(&key, data, cache_control_for_tile(path))
            .await
    }

    async fn read_checkpoint(&self) -> Result<Option<Vec<u8>>, TransparencyError> {
        let key = self.object_key("checkpoint");
        self.get_object(&key).await
    }

    async fn write_checkpoint(&self, data: &[u8]) -> Result<(), TransparencyError> {
        let key = self.object_key("checkpoint");
        self.put_object(&key, data, CACHE_SHORT).await
    }
}

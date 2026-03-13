use crate::error::TransparencyError;

/// Tile height (number of hash levels per tile). C2SP default = 8 → 256 hashes.
pub const TILE_HEIGHT: u32 = 8;

/// Number of leaf hashes per tile (2^TILE_HEIGHT).
pub const TILE_WIDTH: u64 = 1 << TILE_HEIGHT;

/// Encode a tile path per C2SP tlog-tiles spec.
///
/// Segments are zero-padded to 3 digits. Non-final segments get an `x` prefix.
/// E.g., index 1234067 → `x001/x234/067`.
///
/// Args:
/// * `level` — Tile level (0 for data tiles, 1+ for hash tiles).
/// * `index` — Tile index at the given level.
/// * `width` — Partial tile width (0 means full tile, i.e., 256).
///
/// Usage:
/// ```ignore
/// let path = tile_path(0, 1234067, 0)?;
/// assert_eq!(path, "tile/0/x001/x234/067");
/// ```
pub fn tile_path(level: u32, index: u64, width: u64) -> Result<String, TransparencyError> {
    let index_path = encode_index(index)?;
    let mut path = format!("tile/{level}/{index_path}");
    if width > 0 && width < TILE_WIDTH {
        path.push_str(&format!(".p/{width}"));
    }
    Ok(path)
}

/// Encode a tile index into C2SP path segments.
///
/// Zero-padded 3-digit segments, non-final segments prefixed with `x`.
fn encode_index(index: u64) -> Result<String, TransparencyError> {
    if index == 0 {
        return Ok("000".into());
    }

    let mut segments = Vec::new();
    let mut remaining = index;
    while remaining > 0 {
        #[allow(clippy::cast_possible_truncation)]
        let segment = (remaining % 1000) as u16;
        segments.push(segment);
        remaining /= 1000;
    }
    segments.reverse();

    let mut parts = Vec::with_capacity(segments.len());
    for (i, &seg) in segments.iter().enumerate() {
        if i < segments.len() - 1 {
            parts.push(format!("x{seg:03}"));
        } else {
            parts.push(format!("{seg:03}"));
        }
    }
    Ok(parts.join("/"))
}

/// Compute which tile contains a given leaf index.
///
/// Args:
/// * `leaf_index` — Zero-based leaf index.
///
/// Usage:
/// ```ignore
/// let (tile_index, offset) = leaf_tile(42);
/// ```
pub fn leaf_tile(leaf_index: u64) -> (u64, u64) {
    (leaf_index / TILE_WIDTH, leaf_index % TILE_WIDTH)
}

/// Compute the number of full tiles and the partial tile width for a tree of `size` leaves.
///
/// Args:
/// * `size` — Total number of leaves.
///
/// Usage:
/// ```ignore
/// let (full_tiles, partial_width) = tile_count(300);
/// assert_eq!(full_tiles, 1);
/// assert_eq!(partial_width, 44);
/// ```
pub fn tile_count(size: u64) -> (u64, u64) {
    (size / TILE_WIDTH, size % TILE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_index_zero() {
        assert_eq!(encode_index(0).unwrap(), "000");
    }

    #[test]
    fn encode_index_small() {
        assert_eq!(encode_index(5).unwrap(), "005");
        assert_eq!(encode_index(42).unwrap(), "042");
        assert_eq!(encode_index(999).unwrap(), "999");
    }

    #[test]
    fn encode_index_multi_segment() {
        assert_eq!(encode_index(1000).unwrap(), "x001/000");
        assert_eq!(encode_index(1234).unwrap(), "x001/234");
        assert_eq!(encode_index(1234067).unwrap(), "x001/x234/067");
    }

    #[test]
    fn tile_path_data_tile() {
        assert_eq!(tile_path(0, 0, 0).unwrap(), "tile/0/000");
        assert_eq!(tile_path(0, 5, 0).unwrap(), "tile/0/005");
    }

    #[test]
    fn tile_path_partial() {
        assert_eq!(tile_path(0, 0, 42).unwrap(), "tile/0/000.p/42");
    }

    #[test]
    fn tile_path_hash_tile() {
        assert_eq!(tile_path(1, 3, 0).unwrap(), "tile/1/003");
    }

    #[test]
    fn tile_path_large_index() {
        assert_eq!(tile_path(0, 1234067, 0).unwrap(), "tile/0/x001/x234/067");
    }

    #[test]
    fn leaf_tile_computation() {
        assert_eq!(leaf_tile(0), (0, 0));
        assert_eq!(leaf_tile(255), (0, 255));
        assert_eq!(leaf_tile(256), (1, 0));
        assert_eq!(leaf_tile(300), (1, 44));
    }

    #[test]
    fn tile_count_computation() {
        assert_eq!(tile_count(0), (0, 0));
        assert_eq!(tile_count(256), (1, 0));
        assert_eq!(tile_count(300), (1, 44));
        assert_eq!(tile_count(512), (2, 0));
    }
}

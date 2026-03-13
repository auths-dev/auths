use auths_transparency::tile::{TILE_WIDTH, leaf_tile, tile_count, tile_path};

#[test]
fn tile_path_zero_index() {
    assert_eq!(tile_path(0, 0, 0).unwrap(), "tile/0/000");
}

#[test]
fn tile_path_small_indices() {
    assert_eq!(tile_path(0, 1, 0).unwrap(), "tile/0/001");
    assert_eq!(tile_path(0, 42, 0).unwrap(), "tile/0/042");
    assert_eq!(tile_path(0, 999, 0).unwrap(), "tile/0/999");
}

#[test]
fn tile_path_multi_segment_c2sp_spec() {
    // C2SP spec example: 1234067 → x001/x234/067
    assert_eq!(tile_path(0, 1234067, 0).unwrap(), "tile/0/x001/x234/067");
}

#[test]
fn tile_path_two_segment() {
    assert_eq!(tile_path(0, 1000, 0).unwrap(), "tile/0/x001/000");
    assert_eq!(tile_path(0, 1234, 0).unwrap(), "tile/0/x001/234");
}

#[test]
fn tile_path_hash_level() {
    assert_eq!(tile_path(1, 5, 0).unwrap(), "tile/1/005");
    assert_eq!(tile_path(2, 0, 0).unwrap(), "tile/2/000");
}

#[test]
fn tile_path_partial_tile() {
    assert_eq!(tile_path(0, 0, 42).unwrap(), "tile/0/000.p/42");
    assert_eq!(tile_path(0, 5, 128).unwrap(), "tile/0/005.p/128");
}

#[test]
fn tile_path_full_width_no_suffix() {
    // width == TILE_WIDTH (256) is treated same as 0 → full tile, no .p suffix
    assert_eq!(tile_path(0, 0, 0).unwrap(), "tile/0/000");
}

#[test]
fn leaf_tile_within_first_tile() {
    assert_eq!(leaf_tile(0), (0, 0));
    assert_eq!(leaf_tile(1), (0, 1));
    assert_eq!(leaf_tile(255), (0, 255));
}

#[test]
fn leaf_tile_boundary() {
    assert_eq!(leaf_tile(256), (1, 0));
    assert_eq!(leaf_tile(257), (1, 1));
}

#[test]
fn tile_count_exact_multiples() {
    assert_eq!(tile_count(0), (0, 0));
    assert_eq!(tile_count(TILE_WIDTH), (1, 0));
    assert_eq!(tile_count(TILE_WIDTH * 3), (3, 0));
}

#[test]
fn tile_count_with_remainder() {
    assert_eq!(tile_count(1), (0, 1));
    assert_eq!(tile_count(300), (1, 44));
    assert_eq!(tile_count(TILE_WIDTH + 1), (1, 1));
}

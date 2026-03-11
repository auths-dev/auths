use std::path::PathBuf;

use auths_utils::path::expand_tilde;

#[test]
fn tilde_prefix_expands_to_home() {
    let result = expand_tilde(&PathBuf::from("~/.auths")).unwrap();
    assert!(!result.to_string_lossy().contains('~'));
    assert!(result.ends_with(".auths"));
}

#[test]
fn bare_tilde_expands_to_home() {
    let result = expand_tilde(&PathBuf::from("~")).unwrap();
    #[allow(clippy::disallowed_methods)]
    let home = dirs::home_dir().unwrap();
    assert_eq!(result, home);
}

#[test]
fn absolute_path_unchanged() {
    let result = expand_tilde(&PathBuf::from("/tmp/auths")).unwrap();
    assert_eq!(result, PathBuf::from("/tmp/auths"));
}

#[test]
fn relative_path_unchanged() {
    let result = expand_tilde(&PathBuf::from("relative/path")).unwrap();
    assert_eq!(result, PathBuf::from("relative/path"));
}

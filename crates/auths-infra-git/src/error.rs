use auths_core::ports::storage::StorageError;
use git2::{Error as Git2Error, ErrorClass, ErrorCode};

pub(crate) fn map_git2_error(err: Git2Error) -> StorageError {
    match err.class() {
        ErrorClass::Reference => map_reference_error(err),
        ErrorClass::Object | ErrorClass::Odb => map_object_error(err),
        ErrorClass::Os | ErrorClass::Repository => map_io_error(err),
        _ => map_by_code(err),
    }
}

pub(crate) fn map_reference_error(err: Git2Error) -> StorageError {
    if err.code() == ErrorCode::NotFound {
        StorageError::NotFound {
            path: extract_path_hint(&err),
        }
    } else {
        StorageError::Io(err.to_string())
    }
}

pub(crate) fn map_object_error(err: Git2Error) -> StorageError {
    if err.code() == ErrorCode::NotFound {
        StorageError::NotFound {
            path: extract_path_hint(&err),
        }
    } else {
        StorageError::Io(err.to_string())
    }
}

pub(crate) fn map_io_error(err: Git2Error) -> StorageError {
    if err.code() == ErrorCode::NotFound {
        StorageError::NotFound {
            path: extract_path_hint(&err),
        }
    } else if err.code() == ErrorCode::Exists {
        StorageError::AlreadyExists {
            path: extract_path_hint(&err),
        }
    } else {
        StorageError::Io(err.to_string())
    }
}

fn map_by_code(err: Git2Error) -> StorageError {
    match err.code() {
        ErrorCode::NotFound => StorageError::NotFound {
            path: extract_path_hint(&err),
        },
        ErrorCode::Exists => StorageError::AlreadyExists {
            path: extract_path_hint(&err),
        },
        _ => StorageError::Io(err.to_string()),
    }
}

fn extract_path_hint(err: &Git2Error) -> String {
    err.message().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_reference_error_non_not_found_becomes_io() {
        let git_err = Git2Error::from_str("ref error");
        let result = map_reference_error(git_err);
        assert!(matches!(result, StorageError::Io(_)));
    }

    #[test]
    fn map_object_error_non_not_found_becomes_io() {
        let git_err = Git2Error::from_str("object error");
        let result = map_object_error(git_err);
        assert!(matches!(result, StorageError::Io(_)));
    }

    #[test]
    fn map_io_error_generic() {
        let git_err = Git2Error::from_str("disk full");
        let result = map_io_error(git_err);
        assert!(matches!(result, StorageError::Io(_)));
    }

    #[test]
    fn map_git2_error_generic() {
        let git_err = Git2Error::from_str("something went wrong");
        let storage_err = map_git2_error(git_err);
        assert!(matches!(storage_err, StorageError::Io(_)));
    }

    #[test]
    fn map_by_code_generic_becomes_io() {
        let git_err = Git2Error::from_str("unknown");
        let result = map_by_code(git_err);
        assert!(matches!(result, StorageError::Io(_)));
    }

    #[test]
    fn not_found_tested_via_real_repo() {
        let dir = tempfile::TempDir::new().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let err = repo
            .find_reference("refs/nonexistent")
            .err()
            .expect("should fail for nonexistent ref");
        let result = map_git2_error(err);
        assert!(matches!(result, StorageError::NotFound { .. }));
    }
}

use auths_core::ports::network::NetworkError;

pub(crate) fn map_reqwest_error(err: reqwest::Error, endpoint: &str) -> NetworkError {
    if err.is_timeout() {
        map_timeout_error(endpoint)
    } else if err.is_connect() {
        map_connection_error(endpoint)
    } else {
        NetworkError::Internal(Box::new(err))
    }
}

pub(crate) fn map_timeout_error(endpoint: &str) -> NetworkError {
    NetworkError::Timeout {
        endpoint: endpoint.to_string(),
    }
}

pub(crate) fn map_connection_error(endpoint: &str) -> NetworkError {
    NetworkError::Unreachable {
        endpoint: endpoint.to_string(),
    }
}

pub(crate) fn map_status_error(status: u16, resource: &str) -> NetworkError {
    match status {
        404 => NetworkError::NotFound {
            resource: resource.to_string(),
        },
        401 | 403 => NetworkError::Unauthorized,
        _ => NetworkError::InvalidResponse {
            detail: format!("HTTP {}", status),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_timeout_error_produces_timeout() {
        let err = map_timeout_error("example.com");
        assert!(matches!(err, NetworkError::Timeout { .. }));
    }

    #[test]
    fn map_connection_error_produces_unreachable() {
        let err = map_connection_error("example.com");
        assert!(matches!(err, NetworkError::Unreachable { .. }));
    }

    #[test]
    fn map_status_404_produces_not_found() {
        let err = map_status_error(404, "/path");
        assert!(matches!(err, NetworkError::NotFound { .. }));
    }

    #[test]
    fn map_status_401_produces_unauthorized() {
        let err = map_status_error(401, "/path");
        assert!(matches!(err, NetworkError::Unauthorized));
    }

    #[test]
    fn map_status_403_produces_unauthorized() {
        let err = map_status_error(403, "/path");
        assert!(matches!(err, NetworkError::Unauthorized));
    }

    #[test]
    fn map_status_500_produces_invalid_response() {
        let err = map_status_error(500, "/path");
        assert!(matches!(err, NetworkError::InvalidResponse { .. }));
    }
}

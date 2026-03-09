use napi::Status;

pub fn map_error(err: impl std::fmt::Display) -> napi::Error {
    let msg = err.to_string();
    napi::Error::new(Status::GenericFailure, msg)
}

pub fn format_error(code: &str, message: impl std::fmt::Display) -> napi::Error {
    napi::Error::new(Status::GenericFailure, format!("[{code}] {message}"))
}

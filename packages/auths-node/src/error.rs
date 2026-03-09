use napi::Status;

pub fn format_error(code: &str, message: impl std::fmt::Display) -> napi::Error {
    napi::Error::new(Status::GenericFailure, format!("[{code}] {message}"))
}

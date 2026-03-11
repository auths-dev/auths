/// Masks credentials in a URL by replacing the user:password portion with `***`.
///
/// Args:
/// * `url`: A URL string that may contain embedded credentials.
///
/// Usage:
/// ```
/// # use auths_utils::url::mask_url;
/// let masked = mask_url("postgres://user:pass@host/db");
/// assert_eq!(masked, "postgres://***@host/db");
/// ```
pub fn mask_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@')
        && let Some(scheme_end) = url.find("://")
    {
        return format!("{}://***@{}", &url[..scheme_end], &url[at_pos + 1..]);
    }
    url.to_string()
}

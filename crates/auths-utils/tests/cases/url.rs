use auths_utils::url::mask_url;

#[test]
fn url_with_credentials_masked() {
    let masked = mask_url("postgres://admin:secret@db.example.com:5432/mydb");
    assert_eq!(masked, "postgres://***@db.example.com:5432/mydb");
}

#[test]
fn url_without_at_unchanged() {
    let url = "https://example.com/path";
    assert_eq!(mask_url(url), url);
}

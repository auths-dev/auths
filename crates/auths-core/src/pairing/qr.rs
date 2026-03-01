//! QR code generation for pairing tokens.

use qrcode::QrCode;
use qrcode::render::unicode;

use super::error::PairingError;
use super::token::PairingToken;

/// QR code rendering options.
#[derive(Debug, Clone)]
pub struct QrOptions {
    /// Use compact rendering (half-block characters).
    pub compact: bool,
    /// Quiet zone (border) size in modules.
    pub quiet_zone: u32,
    /// Invert colors (light on dark).
    pub invert: bool,
}

impl Default for QrOptions {
    fn default() -> Self {
        Self {
            compact: true,
            quiet_zone: 1,
            invert: false,
        }
    }
}

/// Render a pairing token as a QR code string for terminal display.
pub fn render_qr(token: &PairingToken, options: &QrOptions) -> Result<String, PairingError> {
    let uri = token.to_uri();
    render_qr_from_data(&uri, options)
}

/// Render arbitrary data as a QR code string for terminal display.
pub fn render_qr_from_data(data: &str, options: &QrOptions) -> Result<String, PairingError> {
    let code =
        QrCode::new(data.as_bytes()).map_err(|e| PairingError::QrCodeFailed(e.to_string()))?;

    let qr_string = if options.compact {
        // Use half-block characters for compact rendering
        let (dark, light) = if options.invert {
            (unicode::Dense1x2::Light, unicode::Dense1x2::Dark)
        } else {
            (unicode::Dense1x2::Dark, unicode::Dense1x2::Light)
        };

        code.render::<unicode::Dense1x2>()
            .dark_color(dark)
            .light_color(light)
            .quiet_zone(options.quiet_zone > 0)
            .build()
    } else {
        // Use full-block characters
        let (dark, light) = if options.invert {
            (' ', '\u{2588}')
        } else {
            ('\u{2588}', ' ')
        };

        code.render::<char>()
            .dark_color(dark)
            .light_color(light)
            .quiet_zone(options.quiet_zone > 0)
            .build()
    };

    Ok(qr_string)
}

/// Format a pairing QR code with header text for terminal display.
///
/// Returns the complete formatted output as a String. The caller is
/// responsible for printing it.
pub fn format_pairing_qr(token: &PairingToken) -> Result<String, PairingError> {
    let options = QrOptions::default();
    let qr = render_qr(token, &options)?;

    let mut output = String::new();
    output.push('\n');
    output.push_str("Scan this QR code with your other device:\n");
    output.push('\n');
    output.push_str(&qr);
    output.push('\n');
    output.push('\n');
    output.push_str(&format!(
        "Or enter this code manually: {}\n",
        token.short_code
    ));
    output.push('\n');
    output.push_str(&format!("Controller: {}\n", token.controller_did));
    if !token.capabilities.is_empty() {
        output.push_str(&format!(
            "Capabilities: {}\n",
            token.capabilities.join(", ")
        ));
    }
    output.push_str(&format!(
        "Expires: {}\n",
        token.expires_at.format("%H:%M:%S")
    ));
    output.push('\n');

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token() -> PairingToken {
        PairingToken::generate(
            chrono::Utc::now(),
            "did:keri:test123".to_string(),
            "http://localhost:3000".to_string(),
            vec!["sign_commit".to_string()],
        )
        .unwrap()
        .token
    }

    #[test]
    fn test_render_qr() {
        let token = make_token();
        let options = QrOptions::default();

        let qr = render_qr(&token, &options).unwrap();
        assert!(!qr.is_empty());
        // Should contain unicode block characters
        assert!(qr.contains('\u{2580}') || qr.contains('\u{2584}') || qr.contains('\u{2588}'));
    }

    #[test]
    fn test_render_qr_inverted() {
        let token = make_token();
        let options = QrOptions {
            invert: true,
            ..Default::default()
        };

        let qr = render_qr(&token, &options).unwrap();
        assert!(!qr.is_empty());
    }

    #[test]
    fn test_render_qr_non_compact() {
        let token = make_token();
        let options = QrOptions {
            compact: false,
            ..Default::default()
        };

        let qr = render_qr(&token, &options).unwrap();
        assert!(!qr.is_empty());
    }
}

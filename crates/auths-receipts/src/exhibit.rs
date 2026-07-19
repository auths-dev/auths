//! The generic exhibit renderer (plan RC-E3.4a): a minimal, dependency-free PDF
//! carrying the bundle's human render plus a verification appendix with the
//! offline-check instructions. Per-PSP field mappings are decide-gated and land
//! with a design partner — never guessed here.

/// Render text lines into a minimal single-page PDF 1.4 (Helvetica 10pt).
///
/// Args:
/// * `title`: the exhibit title line.
/// * `lines`: the body lines (long lines are wrapped at 100 chars).
///
/// Usage:
/// ```ignore
/// let pdf = pdf_exhibit("Dispute evidence — tx 0x…", &lines);
/// ```
pub fn pdf_exhibit(title: &str, lines: &[String]) -> Vec<u8> {
    let mut wrapped: Vec<String> = vec![title.to_string(), String::new()];
    for line in lines {
        if line.is_empty() {
            wrapped.push(String::new());
            continue;
        }
        let mut rest = line.as_str();
        while rest.len() > 100 {
            let (head, tail) = rest.split_at(100);
            wrapped.push(head.to_string());
            rest = tail;
        }
        wrapped.push(rest.to_string());
    }

    let mut content = String::from("BT /F1 10 Tf 40 800 Td 12 TL\n");
    for line in &wrapped {
        let escaped = line
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)");
        content.push_str(&format!("({escaped}) Tj T*\n"));
    }
    content.push_str("ET\n");

    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!("<< /Length {} >>\nstream\n{content}endstream", content.len()),
    ];

    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{object}\nendobj\n", index + 1));
    }
    let xref_at = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1));
    for offset in &offsets {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
        objects.len() + 1
    ));
    pdf.into_bytes()
}

/// The verification appendix every exhibit carries — the offline-check
/// instructions that make the exhibit auditable rather than merely asserted.
pub fn verification_appendix() -> Vec<String> {
    vec![
        String::new(),
        "--- VERIFICATION APPENDIX ---".to_string(),
        "This exhibit is a RENDER of a signed, self-contained EvidenceBundle (receipts/v1).".to_string(),
        "Do not trust this render. Re-derive the verdicts from the bundle itself:".to_string(),
        "  1. Obtain the bundle JSON that accompanies this exhibit.".to_string(),
        "  2. Run `receipt_verify` (MCP) or POST /v1/verify (HTTP), or call".to_string(),
        "     verifyOffline() from @auths-dev/sdk — fully offline, no network.".to_string(),
        "  3. Assert the echoed subject / tx / callIndex match the disputed payment".to_string(),
        "     (a valid bundle about a DIFFERENT call is not evidence about yours).".to_string(),
        "  4. The verdict is always \"as of\" the anchor head the bundle states —".to_string(),
        "     check the anchor tier and timestamp meet your freshness policy.".to_string(),
    ]
}

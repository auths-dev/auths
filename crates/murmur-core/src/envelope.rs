//! The two-layer envelope — routing on the outside, a verified session inside.
//!
//! The phone number smushed routing and identity together; splitting them is
//! strictly better for metadata privacy. The relay only ever touches the
//! [`OuterEnvelope`]; only the recipient device ever reconstructs the
//! [`InnerEnvelope`].
//!
//! ## Wire encoding — a compact, versioned BINARY frame
//! Both envelopes serialize to a hand-rolled big-endian frame (not JSON: a JSON
//! number array bloats opaque bytes ~3×). A leading version byte gates format
//! evolution; variable fields are length-prefixed. The relay's at-rest + HTTP
//! formats and the FFI seal/open all use [`OuterEnvelope::to_frame`]; the sealed
//! payload uses [`InnerEnvelope::to_frame`].

use serde::{Deserialize, Serialize};

use crate::relay::MailboxId;
use crate::{CoreError, CoreResult};

/// Frame format version for both envelopes (bump on an incompatible layout change).
const FRAME_V1: u8 = 1;

/// What the untrusted relay sees: a pairwise mailbox id and opaque ciphertext.
/// No sender AID, no plaintext, no phone number — routing only. (Keeps serde for
/// [`crate::RelayRequest`]; the wire/at-rest path uses [`to_frame`](Self::to_frame).)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OuterEnvelope {
    /// The pairwise/rotating mailbox the bytes are queued under.
    pub to_mailbox: MailboxId,
    /// Opaque, end-to-end-encrypted bytes. The relay cannot read these.
    pub ciphertext: Vec<u8>,
}

impl OuterEnvelope {
    /// A stand-in envelope for tests and skeleton call sites.
    pub fn placeholder() -> Self {
        OuterEnvelope {
            to_mailbox: MailboxId::placeholder(),
            ciphertext: Vec::new(),
        }
    }

    /// Encode as `[ver:u8][mbx_len:u16][mbx][ciphertext…]`.
    pub fn to_frame(&self) -> CoreResult<Vec<u8>> {
        let mbx = self.to_mailbox.as_str().as_bytes();
        let mut out = Vec::with_capacity(3 + mbx.len() + self.ciphertext.len());
        out.push(FRAME_V1);
        put_u16_prefixed(&mut out, mbx)?;
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Decode a frame produced by [`to_frame`](Self::to_frame).
    pub fn from_frame(frame: &[u8]) -> CoreResult<OuterEnvelope> {
        let mut r = FrameReader::new(frame);
        let ver = r.u8()?;
        if ver != FRAME_V1 {
            return Err(CoreError::Malformed(format!("outer frame version {ver}")));
        }
        let mbx = r.take_u16_prefixed()?;
        let mailbox = std::str::from_utf8(mbx)
            .map_err(|_| CoreError::Malformed("mailbox not utf-8".into()))?;
        Ok(OuterEnvelope {
            to_mailbox: MailboxId::new(mailbox),
            ciphertext: r.rest().to_vec(),
        })
    }
}

/// Inner frame version (bumped from v1: compact sender, recipient not stored, variable
/// message_id, optional content_type/flags).
const INNER_FRAME_V2: u8 = 2;

/// What the recipient reconstructs after AEAD-opening the outer envelope. The whole
/// struct is sealed inside the [`OuterEnvelope`]'s ciphertext, so the relay never sees any
/// of these fields.
///
/// **Size: per-mailbox-constant data is not stored per message.** A pairwise session's two
/// endpoints are already known, so the `recipient` is *not* stored in the frame at all (the
/// opener reconstructs it as itself), and the `sender` AID is stored as its compact 32-byte
/// digest, not the `did:keri:<64-hex>` string. `content_type`/`flags` are omitted entirely
/// when default. All fields are still **signed** (see [`signing_bytes`]).
///
/// [`signing_bytes`]: InnerEnvelope::signing_bytes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnerEnvelope {
    /// The claimed sender AID — authenticated by verifying `signature` against the key this
    /// AID resolves to, never trusted because it was asserted.
    pub sender: crate::address::Aid,
    /// The recipient AID the body was authored for, bound into the signed bytes. **Not
    /// stored in the frame** — in a pairwise session the recipient is the opener itself, so
    /// [`from_frame`](Self::from_frame) takes it from the caller. Kept here for the signature.
    pub recipient: crate::address::Aid,
    /// A stable end-to-end message id (variable length). Enables recipient-side dedup +
    /// receipts + edit/delete once built; a per-conversation sequence is the smaller,
    /// order-preserving choice the app supplies via `seal_with`.
    pub message_id: Vec<u8>,
    /// The body's content type (default `"text"`, then omitted from the frame). For
    /// attachments/voice a later build sets e.g. `"voice"`/`"file"` + a storage-pointer body.
    pub content_type: String,
    /// Per-message flags (default 0, then omitted from the frame). Reserved for disappearing
    /// timers + multi-device routing.
    pub flags: u32,
    /// The user's message body, authenticated by `signature`.
    pub body: String,
    /// The sender's signature over the authenticated bytes (see [`signing_bytes`]).
    ///
    /// [`signing_bytes`]: InnerEnvelope::signing_bytes
    pub signature: Vec<u8>,
}

impl InnerEnvelope {
    /// The canonical byte string a sender signs and a recipient verifies. Binds every
    /// authenticated field (sender, recipient, message_id, content_type, flags, body) —
    /// `recipient` included even though it is not *stored*, so a captured envelope cannot be
    /// re-attributed to another conversation. Length-prefixed so no field is ambiguous.
    pub fn signing_bytes(
        sender: &crate::address::Aid,
        recipient: &crate::address::Aid,
        message_id: &[u8],
        content_type: &str,
        flags: u32,
        body: &str,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"murmur/inner/v3\n");
        let _ = put_u16_prefixed(&mut bytes, sender.as_str().as_bytes());
        let _ = put_u16_prefixed(&mut bytes, recipient.as_str().as_bytes());
        let _ = put_u8_prefixed(&mut bytes, message_id);
        let _ = put_u8_prefixed(&mut bytes, content_type.as_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(body.as_bytes());
        bytes
    }

    /// The signing bytes for *this* envelope — what [`crate::Endpoint::open`] re-derives.
    pub fn signing_bytes_for(&self) -> Vec<u8> {
        Self::signing_bytes(
            &self.sender,
            &self.recipient,
            &self.message_id,
            &self.content_type,
            self.flags,
            &self.body,
        )
    }

    /// Encode as `[ver=2][sender:compact-aid][message_id:lp8][present:u8]
    /// [content_type:lp8 if present.0][flags:u32 if present.1][sig:lp16][body…]`. The
    /// recipient is NOT written (the opener knows it is itself).
    pub fn to_frame(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        out.push(INNER_FRAME_V2);
        put_aid(&mut out, &self.sender)?;
        put_u8_prefixed(&mut out, &self.message_id)?;
        let ct_present = self.content_type != "text";
        let flags_present = self.flags != 0;
        let present = (ct_present as u8) | ((flags_present as u8) << 1);
        out.push(present);
        if ct_present {
            put_u8_prefixed(&mut out, self.content_type.as_bytes())?;
        }
        if flags_present {
            out.extend_from_slice(&self.flags.to_be_bytes());
        }
        put_u16_prefixed(&mut out, &self.signature)?;
        out.extend_from_slice(self.body.as_bytes());
        Ok(out)
    }

    /// Decode a frame produced by [`to_frame`](Self::to_frame). `recipient` is supplied by
    /// the caller (the opening endpoint is the recipient); it is not in the frame.
    pub fn from_frame(frame: &[u8], recipient: &crate::address::Aid) -> CoreResult<InnerEnvelope> {
        let mut r = FrameReader::new(frame);
        let ver = r.u8()?;
        if ver != INNER_FRAME_V2 {
            return Err(CoreError::Malformed(format!("inner frame version {ver}")));
        }
        let sender = take_aid(&mut r)?;
        let message_id = r.take_u8_prefixed()?.to_vec();
        let present = r.u8()?;
        let content_type = if present & 0x01 != 0 {
            std::str::from_utf8(r.take_u8_prefixed()?)
                .map_err(|_| CoreError::Malformed("content_type not utf-8".into()))?
                .to_string()
        } else {
            "text".to_string()
        };
        let flags = if present & 0x02 != 0 { r.u32()? } else { 0 };
        let signature = r.take_u16_prefixed()?.to_vec();
        let body = std::str::from_utf8(r.rest())
            .map_err(|_| CoreError::Malformed("body not utf-8".into()))?
            .to_string();
        Ok(InnerEnvelope {
            sender,
            recipient: recipient.clone(),
            message_id,
            content_type,
            flags,
            body,
            signature,
        })
    }
}

/// Write an AID compactly: `[kind:u8]` then either the 32-byte digest of a self-certifying
/// `did:keri:<64-hex>` (kind 0, ~33 B) or the UTF-8 string for any other AID (kind 1).
fn put_aid(out: &mut Vec<u8>, aid: &crate::address::Aid) -> CoreResult<()> {
    let s = aid.as_str();
    if let Some(hex) = s.strip_prefix("did:keri:") {
        if let Some(digest) = decode_hex32(hex) {
            out.push(0);
            out.extend_from_slice(&digest);
            return Ok(());
        }
    }
    out.push(1);
    put_u16_prefixed(out, s.as_bytes())
}

/// Read an AID written by [`put_aid`].
fn take_aid(r: &mut FrameReader) -> CoreResult<crate::address::Aid> {
    match r.u8()? {
        0 => {
            let digest = r.take(32)?;
            Ok(crate::address::Aid::new(format!("did:keri:{}", encode_hex(digest))))
        }
        1 => {
            let s = std::str::from_utf8(r.take_u16_prefixed()?)
                .map_err(|_| CoreError::Malformed("aid not utf-8".into()))?;
            Ok(crate::address::Aid::new(s))
        }
        other => Err(CoreError::Malformed(format!("unknown aid kind {other}"))),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let b = hex.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_val(b[2 * i])? << 4) | hex_val(b[2 * i + 1])?;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn put_u16_prefixed(out: &mut Vec<u8>, data: &[u8]) -> CoreResult<()> {
    let len = u16::try_from(data.len())
        .map_err(|_| CoreError::Malformed("field too long for u16 length".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn put_u8_prefixed(out: &mut Vec<u8>, data: &[u8]) -> CoreResult<()> {
    let len = u8::try_from(data.len())
        .map_err(|_| CoreError::Malformed("field too long for u8 length".into()))?;
    out.push(len);
    out.extend_from_slice(data);
    Ok(())
}

/// A bounds-checked cursor over a frame; any short read is a `Malformed` error.
struct FrameReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FrameReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        FrameReader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> CoreResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(short)?;
        if end > self.buf.len() {
            return Err(short());
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> CoreResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> CoreResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> CoreResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn take_u16_prefixed(&mut self) -> CoreResult<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    fn take_u8_prefixed(&mut self) -> CoreResult<&'a [u8]> {
        let len = self.u8()? as usize;
        self.take(len)
    }

    fn rest(self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

fn short() -> CoreError {
    CoreError::Malformed("frame truncated".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Aid;

    #[test]
    fn outer_frame_round_trips() {
        let env = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx-abc123"),
            ciphertext: vec![0, 1, 2, 250, 255, 10],
        };
        let frame = env.to_frame().unwrap();
        assert_eq!(OuterEnvelope::from_frame(&frame).unwrap(), env);
    }

    #[test]
    fn inner_frame_round_trips_with_all_fields() {
        // A real did:keri AID (64 hex) exercises the compact 32-byte-digest path.
        let recipient = Aid::new(format!("did:keri:{}", "a".repeat(64)));
        let inner = InnerEnvelope {
            sender: Aid::new(format!("did:keri:{}", "b".repeat(64))),
            recipient: recipient.clone(),
            message_id: vec![7u8; 8],
            content_type: "voice".to_string(),
            flags: 0xDEAD_BEEF,
            body: "hello\nworld with a newline".to_string(),
            signature: vec![9u8; 64],
        };
        let frame = inner.to_frame().unwrap();
        // The recipient is not in the frame — the opener supplies it (itself).
        let back = InnerEnvelope::from_frame(&frame, &recipient).unwrap();
        assert_eq!(back, inner);
        assert_eq!(back.signing_bytes_for(), inner.signing_bytes_for());
    }

    #[test]
    fn inner_frame_omits_default_content_type_and_flags_and_stays_compact() {
        let recipient = Aid::new(format!("did:keri:{}", "c".repeat(64)));
        let inner = InnerEnvelope {
            sender: Aid::new(format!("did:keri:{}", "d".repeat(64))),
            recipient: recipient.clone(),
            message_id: vec![1, 2, 3],
            content_type: "text".to_string(),
            flags: 0,
            body: "ok".to_string(),
            signature: vec![5u8; 64],
        };
        let frame = inner.to_frame().unwrap();
        assert_eq!(InnerEnvelope::from_frame(&frame, &recipient).unwrap(), inner);
        // ver(1) + sender(1+32) + msgid(1+3) + present(1) + sig(2+64) + body(2) = 109.
        // No recipient string (~75 B), no content_type ("text"), no flags stored.
        assert!(frame.len() <= 112, "default-fields frame is compact: {}", frame.len());
    }

    #[test]
    fn a_truncated_frame_is_malformed_not_a_panic() {
        let frame = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx"),
            ciphertext: vec![1, 2, 3],
        }
        .to_frame()
        .unwrap();
        assert!(OuterEnvelope::from_frame(&frame[..2]).is_err());
        assert!(InnerEnvelope::from_frame(&[2, 0], &Aid::placeholder()).is_err());
    }
}

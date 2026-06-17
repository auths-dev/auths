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

/// What the recipient reconstructs after AEAD-opening the outer envelope. The whole
/// struct is sealed inside the [`OuterEnvelope`]'s ciphertext, so the relay never
/// sees any of these fields.
///
/// `message_id`, `content_type`, and `flags` are end-to-end metadata carried + signed
/// here (invisible to the relay) so the wire format is final for the features that will
/// consume them (dedup/receipts/edit-delete via the id, attachments via the type,
/// disappearing/multi-device via the flags). They have safe defaults today.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnerEnvelope {
    /// The claimed sender AID — authenticated by verifying [`signature`] against the
    /// key this AID resolves to, never trusted because it was asserted.
    ///
    /// [`signature`]: InnerEnvelope::signature
    pub sender: crate::address::Aid,
    /// The recipient AID the body was authored for, bound into the signed bytes.
    pub recipient: crate::address::Aid,
    /// A stable 16-byte message id (end-to-end). Enables recipient-side dedup +
    /// receipts + edit/delete/reactions once those are built; minted per message.
    pub message_id: [u8; 16],
    /// The body's content type (default `"text"`). For attachments/voice a later
    /// build sets e.g. `"voice"`/`"file"` and puts a storage pointer in the body.
    pub content_type: String,
    /// Per-message flags bitfield (default 0). Reserved for disappearing timers +
    /// multi-device routing/self-sync.
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
    /// authenticated field (sender, recipient, message_id, content_type, flags, body)
    /// with length prefixes so none can be swapped or made ambiguous after signing.
    pub fn signing_bytes(
        sender: &crate::address::Aid,
        recipient: &crate::address::Aid,
        message_id: &[u8; 16],
        content_type: &str,
        flags: u32,
        body: &str,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"murmur/inner/v2\n");
        // Length-prefixed so a binary message_id / flags can't create separator
        // ambiguity. `put_*` cannot overflow here for realistic field sizes; on the
        // impossible overflow we still produce *some* deterministic bytes (a verify
        // mismatch), never a panic.
        let _ = put_u16_prefixed(&mut bytes, sender.as_str().as_bytes());
        let _ = put_u16_prefixed(&mut bytes, recipient.as_str().as_bytes());
        bytes.extend_from_slice(message_id);
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

    /// Encode as `[ver][sender:lp16][recip:lp16][message_id:16][content_type:lp8]
    /// [flags:u32][sig:lp16][body…]`.
    pub fn to_frame(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        out.push(FRAME_V1);
        put_u16_prefixed(&mut out, self.sender.as_str().as_bytes())?;
        put_u16_prefixed(&mut out, self.recipient.as_str().as_bytes())?;
        out.extend_from_slice(&self.message_id);
        put_u8_prefixed(&mut out, self.content_type.as_bytes())?;
        out.extend_from_slice(&self.flags.to_be_bytes());
        put_u16_prefixed(&mut out, &self.signature)?;
        out.extend_from_slice(self.body.as_bytes());
        Ok(out)
    }

    /// Decode a frame produced by [`to_frame`](Self::to_frame).
    pub fn from_frame(frame: &[u8]) -> CoreResult<InnerEnvelope> {
        let mut r = FrameReader::new(frame);
        let ver = r.u8()?;
        if ver != FRAME_V1 {
            return Err(CoreError::Malformed(format!("inner frame version {ver}")));
        }
        let sender = aid_from(r.take_u16_prefixed()?)?;
        let recipient = aid_from(r.take_u16_prefixed()?)?;
        let message_id = r.take_array16()?;
        let content_type = std::str::from_utf8(r.take_u8_prefixed()?)
            .map_err(|_| CoreError::Malformed("content_type not utf-8".into()))?
            .to_string();
        let flags = r.u32()?;
        let signature = r.take_u16_prefixed()?.to_vec();
        let body = std::str::from_utf8(r.rest())
            .map_err(|_| CoreError::Malformed("body not utf-8".into()))?
            .to_string();
        Ok(InnerEnvelope {
            sender,
            recipient,
            message_id,
            content_type,
            flags,
            body,
            signature,
        })
    }
}

fn aid_from(bytes: &[u8]) -> CoreResult<crate::address::Aid> {
    let s = std::str::from_utf8(bytes).map_err(|_| CoreError::Malformed("aid not utf-8".into()))?;
    Ok(crate::address::Aid::new(s))
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

    fn take_array16(&mut self) -> CoreResult<[u8; 16]> {
        let mut a = [0u8; 16];
        a.copy_from_slice(self.take(16)?);
        Ok(a)
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
        let inner = InnerEnvelope {
            sender: Aid::new("did:keri:Esender"),
            recipient: Aid::new("did:keri:Erecipient"),
            message_id: [7u8; 16],
            content_type: "voice".to_string(),
            flags: 0xDEAD_BEEF,
            body: "hello\nworld with a newline".to_string(),
            signature: vec![9u8; 64],
        };
        let frame = inner.to_frame().unwrap();
        let back = InnerEnvelope::from_frame(&frame).unwrap();
        assert_eq!(back, inner);
        // The signing bytes are stable across a frame round-trip.
        assert_eq!(back.signing_bytes_for(), inner.signing_bytes_for());
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
        assert!(InnerEnvelope::from_frame(&[1, 0]).is_err());
    }
}

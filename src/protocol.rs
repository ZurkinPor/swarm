use anyhow::Result;
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Length-prefixed frame codec for TCP streams.
///
/// Wire format: 4-byte big-endian length followed by `length` bytes of payload.
/// The payload bytes are an encrypted serialized Packet.
pub struct FrameCodec;

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

impl Decoder for FrameCodec {
    type Item = bytes::BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame too large: {} bytes (max {})", len, MAX_FRAME_SIZE),
            ));
        }
        if src.len() < 4 + len {
            // Reserve space for the full frame
            src.reserve(4 + len - src.len());
            return Ok(None);
        }
        let _ = src.split_to(4); // discard length prefix
        Ok(Some(src.split_to(len)))
    }
}

impl Encoder<Vec<u8>> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let len = item.len() as u32;
        dst.reserve(4 + item.len());
        dst.put_u32(len);
        dst.extend_from_slice(&item);
        Ok(())
    }
}

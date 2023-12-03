use bytes::{buf::Buf, BytesMut};
use nom::Offset;
use tokio_util::codec::*;
use tracing::trace;

use crate::error::*;
use crate::parser::socks5::*;
use crate::proto::socks5::*;
use crate::proto::WriteBuf;

#[derive(Debug)]
pub struct HandshakeCodec;

impl Decoder for HandshakeCodec {
    type Item = HandshakeRequest;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<HandshakeRequest>, Error> {
        let (consumed, f) = match parse_handshake_request(buf) {
            Ok((i, packet)) => (buf.offset(i), packet),
            Err(e) => {
                if e.is_incomplete() {
                    return Ok(None);
                } else {
                    return Err(parser_error("parse_handshake_request"));
                }
            }
        };

        trace!("socks5 decode; frame={:?}", f);
        buf.advance(consumed);

        Ok(Some(f))
    }
}

impl Encoder<HandshakeResponse> for HandshakeCodec {
    type Error = Error;

    fn encode(&mut self, packet: HandshakeResponse, buf: &mut BytesMut) -> Result<(), Error> {
        packet.write_buf(buf);
        Ok(())
    }
}

#[derive(Debug)]
pub struct CmdCodec;

impl Decoder for CmdCodec {
    type Item = CmdRequest;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<CmdRequest>, Error> {
        let (consumed, f) = match parse_cmd_request(buf) {
            Ok((i, packet)) => (buf.offset(i), packet),
            Err(e) => {
                if e.is_incomplete() {
                    return Ok(None);
                } else {
                    return Err(parser_error(format!("parse_cmd_request, {:?}", e)));
                }
            }
        };

        trace!("socks5 decode; frame={:?}", f);
        buf.advance(consumed);

        Ok(Some(f))
    }
}

impl Encoder<CmdResponse> for CmdCodec {
    type Error = Error;

    fn encode(&mut self, packet: CmdResponse, buf: &mut BytesMut) -> Result<(), Error> {
        packet.write_buf(buf);
        Ok(())
    }
}

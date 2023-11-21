use bytes::BytesMut;
use tokio_util::codec::*;

use crate::error::{parser_error, Error};
use crate::parser::dns::*;
use crate::proto::dns::Message;
use crate::proto::WriteBuf;

#[derive(Debug)]
pub struct MessageCodec;

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Message>, Error> {
        match parse_message(buf) {
            Ok((_i, msg)) => Ok(Some(msg)),
            Err(e) => Err(parser_error(format!("parse_message, {:?}", e))),
        }
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = Error;

    fn encode(&mut self, msg: Message, buf: &mut BytesMut) -> Result<(), Error> {
        msg.write_buf(buf);
        Ok(())
    }
}

use std::{io, marker::PhantomData};
use async_trait::async_trait;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{request_response::Codec, StreamProtocol};
use serde::{de::DeserializeOwned, Serialize};

/// 64 MiB maximum frame size to prevent malicious peers from causing OOM.
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BincodeCodec<Req, Resp> {
    protocol: StreamProtocol,
    _phantom: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> BincodeCodec<Req, Resp> {
    pub fn new(protocol: StreamProtocol) -> Self {
        Self {
            protocol,
            _phantom: PhantomData,
        }
    }

    /// Mengembalikan protokol yang digunakan codec ini.
    /// Berguna untuk debugging, logging, atau verifikasi di masa depan.
    pub fn protocol(&self) -> &StreamProtocol {
        &self.protocol
    }
}

#[async_trait]
impl<Req, Resp> Codec for BincodeCodec<Req, Resp>
where
    Req: Serialize + DeserializeOwned + Send + 'static,
    Resp: Serialize + DeserializeOwned + Send + 'static,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        // Verifikasi ringan bahwa protokol yang dipakai sesuai
        debug_assert_eq!(protocol, self.protocol());

        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        debug_assert_eq!(protocol, self.protocol());

        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        debug_assert_eq!(protocol, self.protocol());

        let bytes = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = (bytes.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&bytes).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        debug_assert_eq!(protocol, self.protocol());

        let bytes = bincode::serialize(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = (bytes.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&bytes).await?;
        Ok(())
    }
}

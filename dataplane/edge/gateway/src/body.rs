use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

pub type BodyError = Box<dyn std::error::Error + Send + Sync>;

pub struct StreamingBody {
    receiver: mpsc::Receiver<Result<Bytes, BodyError>>,
}

impl StreamingBody {
    pub fn new(receiver: mpsc::Receiver<Result<Bytes, BodyError>>) -> Self {
        Self { receiver }
    }
}

pub enum GatewayResponseBody {
    Full(Full<Bytes>),
    Stream(StreamingBody),
}

impl GatewayResponseBody {
    pub fn empty() -> Self {
        GatewayResponseBody::Full(Full::new(Bytes::new()))
    }

    pub fn from_bytes(bytes: Bytes) -> Self {
        GatewayResponseBody::Full(Full::new(bytes))
    }

    pub fn from_static(s: &'static str) -> Self {
        GatewayResponseBody::Full(Full::new(Bytes::from_static(s.as_bytes())))
    }

    pub fn from_string(s: String) -> Self {
        GatewayResponseBody::Full(Full::new(Bytes::from(s)))
    }

    pub fn stream(receiver: mpsc::Receiver<Result<Bytes, BodyError>>) -> Self {
        GatewayResponseBody::Stream(StreamingBody::new(receiver))
    }

    pub fn into_inner(self) -> Option<Bytes> {
        match self {
            GatewayResponseBody::Full(full) => full.into_inner(),
            GatewayResponseBody::Stream(_) => None,
        }
    }

    pub async fn collect_bytes(self) -> Result<Bytes, BodyError> {
        match self {
            GatewayResponseBody::Full(full) => Ok(full.into_inner().unwrap_or_default()),
            GatewayResponseBody::Stream(mut stream) => {
                let mut buf = bytes::BytesMut::new();
                while let Some(chunk_res) = stream.receiver.recv().await {
                    let chunk = chunk_res?;
                    buf.extend_from_slice(&chunk);
                }
                Ok(buf.freeze())
            }
        }
    }
}

impl From<Full<Bytes>> for GatewayResponseBody {
    fn from(full: Full<Bytes>) -> Self {
        GatewayResponseBody::Full(full)
    }
}

impl From<Bytes> for GatewayResponseBody {
    fn from(bytes: Bytes) -> Self {
        GatewayResponseBody::Full(Full::new(bytes))
    }
}

impl Body for GatewayResponseBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            GatewayResponseBody::Full(full) => Pin::new(full)
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(|e| Box::new(e) as BodyError))),
            GatewayResponseBody::Stream(stream) => match stream.receiver.poll_recv(cx) {
                Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            GatewayResponseBody::Full(full) => full.is_end_stream(),
            GatewayResponseBody::Stream(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            GatewayResponseBody::Full(full) => full.size_hint(),
            GatewayResponseBody::Stream(_) => SizeHint::default(),
        }
    }
}

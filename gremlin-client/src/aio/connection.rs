use crate::{GremlinError, GremlinResult};

use crate::connection::ConnectionOptions;

use crate::message::Response;

#[cfg(feature = "async-std-runtime")]
mod async_std_use {
    pub use async_std::net::TcpStream;
    pub use async_std::task;
    pub use async_tls::client::TlsStream;
}

#[cfg(feature = "async-std-runtime")]
use async_std_use::*;

#[cfg(feature = "tokio-runtime")]
mod tokio_use {
    pub use tokio::net::TcpStream;
    pub use tokio::task;
    pub use tokio_native_tls::TlsStream;
}

#[cfg(feature = "tokio-runtime")]
use tokio_use::*;

#[cfg(feature = "async-std-runtime")]
use async_tungstenite::async_std::connect_async_with_tls_connector;

#[cfg(feature = "tokio-runtime")]
use async_tungstenite::tokio::{connect_async_with_tls_connector, TokioAdapter};

use async_tungstenite::tungstenite::client::IntoClientRequest;
use async_tungstenite::tungstenite::protocol::Message;
use async_tungstenite::WebSocketStream;
use async_tungstenite::{self, stream};
use futures::{
    lock::Mutex,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use futures::channel::mpsc::{channel, Receiver, Sender};
use std::collections::HashMap;
use std::sync::Arc;
use url;
use uuid::Uuid;

#[cfg(feature = "async-std-runtime")]
type WSStream = WebSocketStream<stream::Stream<TcpStream, TlsStream<TcpStream>>>;

#[cfg(feature = "tokio-runtime")]
type WSStream =
    WebSocketStream<stream::Stream<TokioAdapter<TcpStream>, TokioAdapter<TlsStream<TcpStream>>>>;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Cmd {
    Msg((Sender<GremlinResult<Response>>, Uuid, Vec<u8>)),
    Pong(Vec<u8>),
    Shutdown,
}

pub(crate) struct Conn {
    sender: Sender<Cmd>,
    valid: bool,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Conn")
    }
}

#[cfg(feature = "neptune-authentication")]
mod neptune_authentication {
    use async_tungstenite::tungstenite::handshake::client::Request;
    use aws_types::credentials::ProvideCredentials;
    use aws_types::region::{Region, SigningRegion};
    use aws_types::SigningService;
    use aws_sig_auth::signer::{OperationSigningConfig, RequestConfig, SigV4Signer};
    use aws_smithy_http::body::SdkBody;
    use std::time::SystemTime;
    use crate::{GremlinError, GremlinResult};

    pub async fn sign_request(req: Request, region: &Region, credentials: &impl ProvideCredentials) -> GremlinResult<Request> {
        let now = SystemTime::now();
        let signer = SigV4Signer::new();
        let request_config = RequestConfig {
            request_ts: now,
            region: &SigningRegion::from(region.clone()),
            service: &SigningService::from_static("neptune-db"),
            payload_override: None,
        };

        // The AWS signer expects an AWS SDK body, whereas there's no body for our websocket requests, so we need to convert
        // back and forth to sign and return the right types.
        let (parts, _) = req.into_parts();
        let mut out = http::Request::from_parts(parts, SdkBody::empty());

        signer.sign(
            &OperationSigningConfig::default_config(),
            &request_config,
            &credentials.provide_credentials().await.map_err(|x| GremlinError::Generic(x.to_string()))?,
            &mut out,
        ).map_err(|x| GremlinError::Generic(x.to_string()))?;

        // Convert back into a Request<()>. Since both are conceptually empty, just have different types, the signature should
        // be unaffected.
        let (out_parts, _) = out.into_parts();
        Ok(Request::from_parts(out_parts, ()))
    }
}

#[cfg(feature = "async-std-runtime")]
mod tls {

    use crate::connection::ConnectionOptions;
    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }

    pub fn connector(opts: &ConnectionOptions) -> Option<async_tls::TlsConnector> {
        use rustls::ClientConfig;
        use std::sync::Arc;
        if opts
            .tls_options
            .as_ref()
            .map(|tls| tls.accept_invalid_certs)
            .unwrap_or(false)
        {
            let mut config = ClientConfig::new();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

            Some(async_tls::TlsConnector::from(Arc::new(config)))
        } else {
            Some(async_tls::TlsConnector::new())
        }
    }
}

#[cfg(feature = "tokio-runtime")]
mod tls {

    use crate::connection::ConnectionOptions;
    use tokio_native_tls::TlsConnector;

    pub fn connector(opts: &ConnectionOptions) -> Option<TlsConnector> {
        opts.tls_options
            .as_ref()
            .and_then(|tls| tls.tls_connector().map(TlsConnector::from).ok())
    }
}
impl Conn {
    pub async fn connect<T>(options: T) -> GremlinResult<Conn>
    where
        T: Into<ConnectionOptions>,
    {
        let opts = options.into();
        let url = url::Url::parse(&opts.websocket_url()).expect("failed to parse url");

        let mut request = url.into_client_request().expect("failed to construct request");

        #[cfg(feature = "neptune-authentication")]
        request.headers_mut().insert("host", match &opts.host_header_override {
            Some(value) => value.clone(),
            None => format!("{}:{}", opts.host, opts.port),
        }.parse().expect("invalid host specified for gremlin connection"));

        #[cfg(feature = "neptune-authentication")]
        let final_request = match &opts.neptune_auth_options {
            Some((region, creds)) => neptune_authentication::sign_request(request, region, creds).await?,
            None => request,
        };

        #[cfg(not(feature = "neptune-authentication"))]
        let final_request = request;

        #[cfg(feature = "async-std-runtime")]
        let (client, _) = { connect_async_with_tls_connector(final_request, tls::connector(&opts)).await? };
        #[cfg(feature = "tokio-runtime")]
        let (client, _) = { connect_async_with_tls_connector(final_request, tls::connector(&opts)).await? };

        let (sink, stream) = client.split();
        let (sender, receiver) = channel(20);
        let requests = Arc::new(Mutex::new(HashMap::new()));

        sender_loop(sink, requests.clone(), receiver);

        receiver_loop(stream, requests.clone(), sender.clone());

        Ok(Conn {
            sender,
            valid: true,
        })
    }

    pub async fn send(
        &mut self,
        id: Uuid,
        payload: Vec<u8>,
    ) -> GremlinResult<(Response, Receiver<GremlinResult<Response>>)> {
        let (sender, mut receiver) = channel(1);

        self.sender
            .send(Cmd::Msg((sender, id, payload)))
            .await
            .map_err(|e| {
                self.valid = false;
                e
            })?;

        receiver
            .next()
            .await
            .expect("It should contain the response")
            .map(|r| (r, receiver))
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        send_shutdown(self);
    }
}

fn send_shutdown(_conn: &mut Conn) {}

fn sender_loop(
    mut sink: SplitSink<WSStream, Message>,
    requests: Arc<Mutex<HashMap<Uuid, Sender<GremlinResult<Response>>>>>,
    mut receiver: Receiver<Cmd>,
) {
    task::spawn(async move {
        loop {
            match receiver.next().await {
                Some(item) => match item {
                    Cmd::Msg(msg) => {
                        let mut guard = requests.lock().await;
                        guard.insert(msg.1, msg.0);
                        if let Err(e) = sink.send(Message::Binary(msg.2)).await {
                            let mut sender = guard.remove(&msg.1).unwrap();
                            sender
                                .send(Err(GremlinError::from(e)))
                                .await
                                .expect("Failed to send error");
                        }
                        drop(guard);
                    }
                    Cmd::Pong(data) => {
                        sink.send(Message::Pong(data))
                            .await
                            .expect("Failed to send pong message.");
                    }
                    Cmd::Shutdown => {
                        let mut guard = requests.lock().await;
                        guard.clear();
                    }
                },
                None => {}
            }
        }
    });
}

fn receiver_loop(
    mut stream: SplitStream<WSStream>,
    requests: Arc<Mutex<HashMap<Uuid, Sender<GremlinResult<Response>>>>>,
    mut sender: Sender<Cmd>,
) {
    task::spawn(async move {
        loop {
            match stream.next().await {
                Some(Err(error)) => {
                    let mut guard = requests.lock().await;
                    for s in guard.values_mut() {
                        match s.send(Err(GremlinError::from(&error))).await {
                            Ok(_r) => {}
                            Err(_e) => {}
                        }
                    }
                    guard.clear();
                }
                Some(Ok(item)) => match item {
                    Message::Binary(data) => {
                        let response: Response = serde_json::from_slice(&data).unwrap();
                        let mut guard = requests.lock().await;
                        if response.status.code != 206 {
                            let item = guard.remove(&response.request_id);
                            drop(guard);
                            if let Some(mut s) = item {
                                match s.send(Ok(response)).await {
                                    Ok(_r) => {}
                                    Err(_e) => {}
                                };
                            }
                        } else {
                            let item = guard.get_mut(&response.request_id);
                            if let Some(s) = item {
                                match s.send(Ok(response)).await {
                                    Ok(_r) => {}
                                    Err(_e) => {}
                                };
                            }
                            drop(guard);
                        }
                    }
                    Message::Ping(data) => sender.send(Cmd::Pong(data)).await.unwrap(),
                    _ => {}
                },
                None => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(feature = "async-std-runtime", async_std::test)]
    #[cfg_attr(feature = "tokio-runtime", tokio::test)]
    async fn it_should_connect() {
        Conn::connect(("localhost", 8182)).await.unwrap();
    }

    #[cfg(feature = "neptune-authentication")]
    #[cfg_attr(feature = "async-std-runtime", async_std::test)]
    #[cfg_attr(feature = "tokio-runtime", tokio::test)]
    async fn it_should_sign() {
        let url = url::Url::parse("wss://myhost:8182").unwrap();

        let mut req = url.into_client_request().unwrap();
        req.headers_mut().insert("host", "myhost:8182".parse().unwrap());

        let region = aws_types::region::Region::from_static("us-west-2");
        let creds = aws_types::Credentials::from_keys("akid", "secret_key", None);

        let signed_req = neptune_authentication::sign_request(req, &region, &creds).await.unwrap();

        let auth_header = signed_req.headers().get("authorization").unwrap().to_str().unwrap();
        assert!(auth_header.starts_with("AWS4-HMAC-SHA256 Credential=akid/"));
    }
}

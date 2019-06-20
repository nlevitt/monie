//! Monie-in-the-middle http(s) proxy library
//!
//! Observe and manipulate requests by implementing `monie::Mitm`. See the
//! examples at <https://github.com/nlevitt/monie/tree/master/examples>.

#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

pub mod certauth;

use std::error::Error;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::{self, Future, FutureResult};
use futures::stream::Stream;
use http::method::Method;
use http::uri::{Authority, Uri};
use hyper::client::pool::Pooled;
use hyper::client::{HttpConnector, PoolClient};
use hyper::server::conn::Http;
use hyper::service::{service_fn, NewService, Service};
use hyper::upgrade::Upgraded;
use hyper::{Body, Chunk, Client, Request, Response};
use hyper_rustls::HttpsConnector;
use tokio_rustls::{Accept, TlsAcceptor, TlsStream};

/// Represents the interception of a single request. Users of the library must
/// implement this trait. With it you can observe and manipulate the request
/// and response payload and headers.
pub trait Mitm {
    /// Create a new instance of this `Mitm` implementation. The argument `uri`
    /// is the uri being proxied. Implementations may do with this what they
    /// wish (log it, stash it, ignore it, etc).
    fn new(uri: Uri) -> Self;

    /// Observe and manipulate the request headers. The `req` argument contains
    /// the original request headers received from the proxy client. The
    /// request headers returned by this function are sent to the remote
    /// server.
    fn request_headers(&self, req: Request<Body>) -> Request<Body>;

    /// Observe and manipulate a chunk of the request payload. This function
    /// may be called zero or more times, depending on the size of the request
    /// payload. It will not be called at all in the common case of a GET
    /// request with no payload. The `chunk` argument contains an original
    /// chunk of the request payload as received from the proxy client. The
    /// return value of this function is sent to the remote server.
    fn request_body_chunk(&self, chunk: Chunk) -> Chunk;

    /// Observe and manipulate the response headers. The `res` argument
    /// contains the original response headers received from the remote server.
    /// The response headers returned by this function are sent to the proxy
    /// client.
    fn response_headers(&self, res: Response<Body>) -> Response<Body>;

    /// Observe and manipulate a chunk of the response payload. This function
    /// may be called zero or more times, depending on the size of the payload.
    /// The `chunk` argument represents an unaltered chunk of the response
    /// payload as received from the remote server. The return value of this
    /// function is sent to the remote server.
    fn response_body_chunk(&self, chunk: Chunk) -> Chunk;
}

lazy_static! {
    static ref CLIENT: Client<HttpsConnector<HttpConnector>, Body> =
        Client::builder().build(HttpsConnector::new(4));
    static ref HTTP: Http = Http::new();
}

/// The `hyper::service::Service` that does the proxying and calls your `Mitm`
/// implementation.
#[derive(Debug)]
pub struct MitmProxyService<T: Mitm + Sync> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Mitm + Sync> MitmProxyService<T> {
    /// Creates a new `MitmProxyService`.
    #[inline]
    pub fn new() -> Self {
        MitmProxyService::<T> {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Mitm + Sync + Send + 'static> NewService for MitmProxyService<T> {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = std::io::Error;
    type Service = MitmProxyService<T>;
    type InitError = std::io::Error;
    type Future = FutureResult<Self::Service, Self::InitError>;

    fn new_service(&self) -> Self::Future {
        future::ok(MitmProxyService::new())
    }
}

impl<T: Mitm + Sync + Send + 'static> Service for MitmProxyService<T> {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = std::io::Error;
    type Future =
        Box<dyn Future<Item = Response<Body>, Error = std::io::Error> + Send>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        info!("MitmProxyService::call() handling {:?}", req);
        if *req.method() == Method::CONNECT {
            Box::new(proxy_connect::<T>(req))
        } else {
            Box::new(proxy_request::<T>(req))
        }
    }
}

/// Obtains a connection to the scheme://authority of `uri` from the connection
/// pool.
fn obtain_connection(
    uri: Uri,
) -> impl Future<Item = Pooled<PoolClient<Body>>, Error = std::io::Error> {
    let key1 = Arc::new(format!(
        "{}://{}",
        uri.scheme_part().unwrap(),
        uri.authority_part().unwrap()
    ));
    let key2 = Arc::clone(&key1);

    let result = CLIENT.connection_for(uri, key1).map_err(move |e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("error obtaining connection to {}: {:?}", key2, e),
        )
    });

    result
}

/// Obtains a connection to the remote server and proxies the request, calling
/// the `Mitm` implementation functions, which may manipulate the request and
/// reponse. Returns a future that resolves to the response or error.
///
/// This function is called for plain http requests, and for https requests
/// received "inside" the fake, tapped `CONNECT` tunnel.
fn proxy_request<T: Mitm + Sync + Send + 'static>(
    req: Request<Body>,
) -> impl Future<Item = Response<Body>, Error = std::io::Error> {
    obtain_connection(req.uri().to_owned())
        .map(|mut connection| {
            let mitm1 = Arc::new(T::new(req.uri().to_owned()));
            let mitm2 = Arc::clone(&mitm1);

            let req = mitm1.request_headers(req);
            let (parts, body) = req.into_parts();
            let body = Body::wrap_stream(
                body.map(move |chunk| mitm1.request_body_chunk(chunk)),
            );
            let req = Request::from_parts(parts, body);

            info!("proxy_request() sending request {:?}", req);
            connection
                .send_request_retryable(req)
                .map(|response| {
                    let response = mitm2.response_headers(response);
                    let (parts, body) = response.into_parts();
                    let body =
                        Body::wrap_stream(body.map(move |chunk| {
                            mitm2.response_body_chunk(chunk)
                        }));
                    Response::from_parts(parts, body)
                })
                .map_err(|(e, _f)| {
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        })
        .flatten()
        .or_else(|e| {
            info!("proxy_request() returning 502 ({})", e);
            future::ok(
                Response::builder().status(502).body(Body::empty()).unwrap(),
            )
        })
}

/// Handles a CONNECT request. Tries to obtain an https connection to the
/// remote server. If that fails, returns 502 Bad Gateway. Otherwise returns
/// 200 OK, then attempts to establish a TLS connection with the proxy client,
/// masquerading as the remote server.
fn proxy_connect<T: Mitm + Sync + Send + 'static>(
    connect_req: Request<Body>,
) -> impl Future<Item = Response<Body>, Error = std::io::Error> {
    info!("proxy_connect() impersonating {:?}", connect_req.uri());
    let authority =
        Authority::from_shared(Bytes::from(connect_req.uri().to_string()))
            .unwrap();
    let tls_cfg = certauth::tls_config(&authority);

    let uri = http::uri::Builder::new()
        .scheme("https")
        .authority(authority)
        .path_and_query("/")
        .build()
        .unwrap();

    obtain_connection(uri)
        .map(move |_pooled| {
            let inner = connect_req.into_body().on_upgrade().map_err(|e| {
                info!("proxy_connect() on_upgrade error: {:?}", e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })
            .and_then(|upgraded: Upgraded| -> Accept<Upgraded> {
                TlsAcceptor::from(tls_cfg).accept(upgraded)
            })
            .map(move |stream: TlsStream<Upgraded, rustls::ServerSession>| {
                info!("proxy_connect() tls connection established with proxy \
                       client: {:?}", stream);
                service_inner_requests::<T>(stream)
            })
            .map_err(|e: std::io::Error| {
                error!("proxy_connect() error from somewhere: {}", e);
            })
            .flatten();

            hyper::rt::spawn(inner);

            Response::builder().status(200).body(Body::empty()).unwrap()
        })
        .or_else(|e| {
            info!("proxy_connect() returning 502, failed to connect: {:?}", e);
            future::ok(
                Response::builder().status(502).body(Body::empty()).unwrap(),
            )
        })
}

/// Called by `proxy_connect()` once the TLS session has been established with
/// the proxy client. Proxies requests received on the TLS connection.
fn service_inner_requests<T: Mitm + Sync + Send + 'static>(
    stream: TlsStream<Upgraded, rustls::ServerSession>,
) -> impl Future<Item = (), Error = ()> {
    let svc = service_fn(move |req: Request<Body>| {
        // "host" header is required for http 1.1
        // XXX but we could fall back on authority
        let authority = req.headers().get("host").unwrap().to_str().unwrap();
        let uri = http::uri::Builder::new()
            .scheme("https")
            .authority(authority)
            .path_and_query(&req.uri().to_string() as &str)
            .build()
            .unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = uri;
        let req = Request::from_parts(parts, body);

        proxy_request::<T>(req)
    });

    HTTP.serve_connection(stream, svc)
        .map_err(|e: hyper::Error| {
            if match e.source() {
                Some(source) => source
                    .to_string()
                    .find("Connection reset by peer")
                    .is_some(),
                None => false,
            } {
                info!(
                    "service_inner_requests() serve_connection: \
                     client closed connection"
                );
            } else {
                error!("service_inner_requests() serve_connection: {}", e);
            };
        })
}

#![deny(warnings)]

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

pub trait Mitm {
    fn new(uri: Uri) -> Self;
    fn request_headers(&self, req: Request<Body>) -> Request<Body>;
    fn request_body_chunk(&self, chunk: Chunk) -> Chunk;
    fn response_headers(&self, res: Response<Body>) -> Response<Body>;
    fn response_body_chunk(&self, chunk: Chunk) -> Chunk;
}

lazy_static! {
    static ref CLIENT: Client<HttpsConnector<HttpConnector>, Body> =
        Client::builder().build(HttpsConnector::new(4));
    static ref HTTP: Http = Http::new();
}

pub struct MitmProxyService<T: Mitm + Sync> {
    _phantom: std::marker::PhantomData<T>,
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

impl<T: Mitm + Sync> MitmProxyService<T> {
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

    let conn = HTTP
        .serve_connection(stream, svc)
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
        });

    conn
}

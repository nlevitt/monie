#![deny(warnings)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

pub mod certauth;

use std::error::Error;
use std::fmt::Display;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::{self, Future, FutureResult};
use futures::stream::Stream;
use http::method::Method;
use http::uri::{Authority, Scheme, Uri};
use hyper::client::pool::Pooled;
use hyper::client::{ClientError, HttpConnector, PoolClient};
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
            Box::new(proxy_connect_https_request::<T>(req))
        } else {
            Box::new(proxy_http_request::<T>(req))
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

fn proxy_request<T: Mitm + Sync + Send + 'static>(
    mitm: T,
    req: Request<Body>,
    pooled: &mut Pooled<PoolClient<Body>>,
) -> impl Future<Item = Response<Body>, Error = std::io::Error> {
    let mitm1 = Arc::new(mitm);
    let mitm2 = Arc::clone(&mitm1);

    let req = mitm1.request_headers(req);
    let (parts, body) = req.into_parts();
    let body = Body::wrap_stream(
        body.map(move |chunk| mitm1.request_body_chunk(chunk)),
    );
    let req = Request::from_parts(parts, body);

    info!("proxy_request() sending request {:?}", req);
    pooled
        .send_request_retryable(req)
        .map(|response| {
            let response = mitm2.response_headers(response);
            let (parts, body) = response.into_parts();
            let body = Body::wrap_stream(
                body.map(move |chunk| mitm2.response_body_chunk(chunk)),
            );
            Response::from_parts(parts, body)
        })
        .map_err(|(e, _f)| {
            info!("e={}", e);
            info!("_f={:?}", _f);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })
}

fn proxy_http_request<T: Mitm + Sync + Send + 'static>(
    mut req: Request<Body>,
) -> impl Future<Item = Response<Body>, Error = std::io::Error> {
    let mitm = T::new(req.uri().to_owned());

    let uri_parts = req.uri_mut().clone().into_parts();

    let fut = pooled_connection(
        uri_parts.scheme.clone().unwrap(),
        uri_parts.authority.clone().unwrap(),
    )
    .map_err(|e| {
        info!(
            "proxy_http_request() returning 502 (error obtaining connection \
             to {}://{}: {:?})",
            uri_parts.scheme.unwrap(),
            uri_parts.authority.unwrap(),
            e
        );
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "error obtaining connection",
        )
    })
    .map(|mut pooled| proxy_request::<T>(mitm, req, &mut pooled))
    .and_then(|res| res)
    .or_else(|_| {
        future::ok(Response::builder().status(502).body(Body::empty()).unwrap())
    });

    fut
}

fn pooled_connection<S: Display + Clone, A: Display + Clone>(
    scheme: S,
    authority: A,
) -> impl Future<Item = Pooled<PoolClient<Body>>, Error = ClientError<Body>>
where
    Scheme: http::HttpTryFrom<S>,
    Authority: http::HttpTryFrom<A>,
{
    let pool_key = Arc::new(
        format!("{}://{}", scheme.clone(), authority.clone()).to_string(),
    );
    let uri = http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query("/")
        .build()
        .unwrap();
    info!(
        "pooled_connection() obtaining connection for uri={} pool_key={}",
        uri, pool_key
    );
    let result = CLIENT.connection_for(uri, pool_key);
    result
}

fn proxy_connect_https_request<T: Mitm + Sync + Send + 'static>(
    connect_req: Request<Body>,
) -> impl Future<Item = Response<Body>, Error = std::io::Error> {
    let authority =
        Authority::from_shared(Bytes::from(connect_req.uri().to_string()))
            .unwrap();
    info!(
        "proxy_connect_https_request() impersonating {:?}",
        authority
    );
    let tls_cfg = certauth::tls_config(&authority);

    pooled_connection("https", authority)
        .map(move |_pooled| {
            let inner = connect_req.into_body().on_upgrade().map_err(|e| {
                info!("proxy_connect_https_request() \
                       on_upgrade error: {:?}", e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })
            .and_then(|upgraded: Upgraded| -> Accept<Upgraded> {
                TlsAcceptor::from(tls_cfg).accept(upgraded)
            })
            .map(move |stream: TlsStream<Upgraded, rustls::ServerSession>| {
                info!("proxy_connect_https_request() tls connection \
                       established with proxy client: {:?}", stream);
                let svc = service_fn(move |req: Request<Body>| {
                    // "host" header is required for http 1.1
                    // XXX but we could fall back on authority
                    let authority = req.headers()
                        .get("host").unwrap()
                        .to_str().unwrap();
                    let uri = http::uri::Builder::new()
                        .scheme("https")
                        .authority(authority)
                        .path_and_query(&req.uri().to_string() as &str)
                        .build()
                        .unwrap();

                    let (mut parts, body) = req.into_parts();
                    parts.uri = uri;
                    let req = Request::from_parts(parts, body);

                    proxy_http_request::<T>(req)
                });

                let conn = HTTP
                    .serve_connection(stream, svc)
                    .map_err(|e: hyper::Error| {
                        if match e.source() {
                            Some(source) => {
                                source.to_string()
                                    .find("Connection reset by peer")
                                    .is_some()
                            },
                                None => false,
                        } {
                            info!("proxy_connect_https_request() \
                                   serve_connection: client closed connection");
                        } else {
                            error!("proxy_connect_https_request() \
                                    serve_connection: {}", e);
                        };
                    });

                conn
            })
            .map_err(|e: std::io::Error| {
                error!("proxy_connect_https_request() error from somewhere: \
                        {}", e);
            })
            .and_then(|conn| conn);

            hyper::rt::spawn(inner);

            Response::builder().status(200).body(Body::empty()).unwrap()
        })
        .or_else(|e| {
            info!("proxy_connect_https_request() returning 502, failed to connect: {:?}", e);
            future::ok(Response::builder().status(502).body(Body::empty()).unwrap())
        })
}

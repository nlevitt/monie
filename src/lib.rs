extern crate hyper;
extern crate futures;
extern crate http;
#[macro_use] extern crate log;
extern crate rustls;
extern crate tokio_rustls;
extern crate hyper_rustls;
#[macro_use] extern crate lazy_static;
extern crate bytes;
extern crate openssl;
extern crate lru_cache;

use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::future::{self, Future, FutureResult};
use futures::{Async, Poll};
use http::uri::{Authority, Scheme, Uri};
use hyper::{Chunk, Request, Method, Response};
use hyper::body::{Body, Payload};
use hyper::client::{self, Client, ResponseFuture, HttpConnector};
use hyper::server::conn::Http;
use hyper::service::{Service, NewService};
use hyper::upgrade::Upgraded;
use hyper_rustls::HttpsConnector;
use lru_cache::LruCache;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use tokio_rustls::{Accept, TlsAcceptor, TlsStream};

#[derive(Debug)]
pub struct ProxyService {
    // value is set from CONNECT line when applicable and used to construct url
    authority: Option<Authority>
}

#[derive(Debug)]
pub struct MitmResponseFuture {
    inner: ResponseFuture
}

#[derive(Debug)]
pub struct MitmBody {
    inner: Body
}

impl Payload for MitmBody {
    type Data = Chunk;
    type Error = hyper::error::Error;

    fn poll_data(&mut self) -> Poll<Option<Self::Data>, Self::Error> {
        match self.inner.poll_data()? {
            Async::Ready(result) => {
                match result {
                    Some(chunk) => {
                        debug!("MitmBody::poll_data() chunk.len()={:?}", chunk.len());
                        Ok(Async::Ready(Some(chunk)))
                    },
                    None => Ok(Async::Ready(None))
                }
            },
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

impl Future for MitmResponseFuture {
    type Item = Response<MitmBody>;
    type Error = hyper::error::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.inner.poll()? {
            Async::Ready(response) => {
                info!("MitmResponseFuture::poll() response={:?}", response);
                let (parts, body) = response.into_parts();
                let mitm_body: MitmBody = MitmBody {inner: body};
                let new_response: Response<MitmBody> = Response::from_parts(parts, mitm_body);
                info!("MitmResponseFuture::poll() new_response={:?}", new_response);
                Ok(Async::Ready(new_response))
            },
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

impl ProxyService {
    pub fn connect(&self, in_req: Request<Body>) -> <ProxyService as Service>::Future {
        let authority = Authority::from_shared(Bytes::from(in_req.uri().to_string())).unwrap();
        info!("ProxyService::connect() impersonating {:?}", authority);
        let tls_cfg = tls_config(&authority);

        let upgrade = in_req.into_body().on_upgrade().map_err(|e| {
            info!("ProxyService::connect() on_upgrade error: {:?}", e);
            io::Error::new(io::ErrorKind::Other, e)
        }).and_then(|upgraded: Upgraded| -> Accept<Upgraded> {
            TlsAcceptor::from(tls_cfg).accept(upgraded)
        }).map(|stream: TlsStream<Upgraded, rustls::ServerSession>| {
            let inner_service = ProxyService{authority: Some(authority)};
            let conn = HTTP.serve_connection(stream, inner_service)
                .map_err(|err: hyper::Error| {
                    error!("ProxyService::connect() serve_connection error: {:?}", err);
                });
            hyper::rt::spawn(conn);
        }).map_err(|err: io::Error| {
            error!("ProxyService::connect() error from somewhere: {}", err);
        });

        hyper::rt::spawn(upgrade);

        // XXX should really establish connection to remote site before responding with 200
        Box::new(future::ok(Response::builder().status(200).body(MitmBody{inner: Body::empty()}).unwrap()))
    }

    pub fn proxy_request(&mut self, in_req: Request<Body>) ->
            <ProxyService as Service>::Future {
        let (mut req_parts, body) = in_req.into_parts();
        if self.authority.is_some() {
            let mut uri_parts = req_parts.uri.into_parts();
            uri_parts.authority = self.authority.clone();
            uri_parts.scheme = Some(Scheme::HTTPS);
            req_parts.uri = Uri::from_parts(uri_parts).unwrap();
        }
        let mitm_req_body = MitmBody {inner: body};
        let out_req: Request<MitmBody> = Request::from_parts(req_parts, mitm_req_body);
        info!("ProxyService::proxy_request() making request: {:?}", out_req);
        let res_fut: ResponseFuture = CLIENT.request(out_req);
        let result: MitmResponseFuture = MitmResponseFuture {inner: res_fut};
        Box::new(result)
    }
}

impl Service for ProxyService {
    type ReqBody = Body;
    type ResBody = MitmBody;
    type Error = hyper::error::Error;
    type Future = Box<Future<Item = Response<MitmBody>, Error = hyper::error::Error> + Send>;

    fn call(&mut self, in_req: Request<Body>) -> Self::Future {
        info!("ProxyService::call() handling {:?}", in_req);
        if *in_req.method() == Method::CONNECT {
            self.connect(in_req)
        } else {
            self.proxy_request(in_req)
        }
    }
}

#[derive(Debug)]
pub struct NewProxyService {}

impl NewService for NewProxyService {
    type ReqBody = Body;
    type ResBody = MitmBody;
    type Error = hyper::error::Error;
    type Service = ProxyService;
    type InitError = hyper::error::Error;
    type Future = FutureResult<Self::Service, Self::InitError>;

    fn new_service(&self) -> Self::Future {
        future::ok(ProxyService{authority: None})
    }
}

lazy_static! {
    static ref CLIENT: Client<HttpsConnector<HttpConnector>, MitmBody> =
        client::Builder::default().build(HttpsConnector::new(4));
    static ref HTTP: Http = Http::new();
    static ref TLS_CONFIG_CACHE: Mutex<LruCache<String, Arc<rustls::ServerConfig>>> = Mutex::new(LruCache::new(1000));
}

pub fn gen_key_cert(authority: &Authority) -> (rustls::PrivateKey, rustls::Certificate) {
    info!("gen_key_cert() generating key/cert for {}", authority.host());

    let rsa: Rsa<openssl::pkey::Private> = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa.clone()).unwrap();
    let key = rustls::PrivateKey(rsa.private_key_to_der().unwrap());

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("CN", authority.host()).unwrap();
    let x509_name = x509_name.build();

    let mut x509builder = X509Builder::new().unwrap();
    x509builder.set_pubkey(&pkey).unwrap();
    x509builder.set_version(2).unwrap();
    x509builder.set_subject_name(&x509_name).unwrap();
    x509builder.set_issuer_name(&x509_name).unwrap();
    x509builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    x509builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    x509builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let x509 = x509builder.build();

    let cert = rustls::Certificate(x509.to_der().unwrap());

    (key, cert)
}

pub fn tls_config(authority: &Authority) -> Arc<rustls::ServerConfig> {
    if !TLS_CONFIG_CACHE.lock().unwrap().contains_key(authority.host()) {
        let tls_cfg: Arc<rustls::ServerConfig> = {
            let (key, cert) = gen_key_cert(&authority);
            let certs = vec![cert; 1];
            let mut result = rustls::ServerConfig::new(rustls::NoClientAuth::new());
            result.set_single_cert(certs, key)
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("{}", e))
                }).unwrap();
            Arc::new(result)
        };

        TLS_CONFIG_CACHE.lock().unwrap().insert(authority.host().to_owned(), tls_cfg);
    }

    TLS_CONFIG_CACHE.lock().unwrap().get_mut(authority.host()).unwrap().clone()
}

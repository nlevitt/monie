//! A simple mitm proxy example using monie. Logs each request with request
//! method, response status code, size and url.

#![deny(warnings)]

use std::sync::Mutex;

use futures::future::Future;
use http::method::Method;
use http::status::StatusCode;
use http::uri::Uri;
use hyper::{Body, Chunk, Request, Response, Server};

use monie::{Mitm, MitmProxyService};

#[derive(Debug)]
struct LogsRequest {
    uri: Uri,
    method: Mutex<Option<Method>>,
    status: Mutex<Option<StatusCode>>,
    length: Mutex<usize>,
}

impl Mitm for LogsRequest {
    fn new(uri: http::uri::Uri) -> LogsRequest {
        LogsRequest {
            uri: uri,
            method: Mutex::new(None),
            status: Mutex::new(None),
            length: Mutex::new(0),
        }
    }

    fn request_headers(&self, req: Request<Body>) -> Request<Body> {
        let (parts, body) = req.into_parts();

        // take note of method for logging
        *self.method.lock().unwrap() = Some(parts.method.clone());

        Request::from_parts(parts, body)
    }

    fn response_headers(&self, res: Response<Body>) -> Response<Body> {
        let (parts, body) = res.into_parts();

        // take note of status for logging
        *self.status.lock().unwrap() = Some(parts.status.clone());

        Response::from_parts(parts, body)
    }

    fn request_body_chunk(&self, chunk: Chunk) -> Chunk {
        chunk
    }

    fn response_body_chunk(&self, chunk: Chunk) -> Chunk {
        // add to length for logging
        *self.length.lock().unwrap() += chunk.len();
        chunk
    }
}

impl Drop for LogsRequest {
    fn drop(&mut self) {
        println!("{:9} {} {} {}",
                 self.length.lock().unwrap(),
                 self.status.lock().unwrap().unwrap().as_u16(),
                 self.method.lock().unwrap().clone().unwrap(),
                 self.uri);
    }
}

fn main() {
    pretty_env_logger::init_timed();
    let addr = ([127, 0, 0, 1], 8000).into();
    let svc = MitmProxyService::<LogsRequest>::new();
    let server = Server::bind(&addr)
        .serve(svc)
        .map_err(|e| eprintln!("server error: {}", e));
    println!("simple mitm proxy listening on http://{}", addr);
    hyper::rt::run(server);
}

extern crate hyper;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate mitmprox;

use std::net::SocketAddr;
use hyper::rt::Future;
use hyper::server::Server;
use hyper::server::conn::AddrIncoming;
use mitmprox::NewProxyService;

fn main() {
    env_logger::Builder::from_default_env()
        .default_format_module_path(true)
        .default_format_timestamp_nanos(true)
        .init();

    let addr: SocketAddr = ([127, 0, 0, 1], 8000).into();
    let new_proxy_service: NewProxyService = NewProxyService{};
    let server: Server<AddrIncoming, NewProxyService> = Server::bind(&addr)
        .serve(new_proxy_service);
    info!("main() listening on {}", addr);

    let server_map_err: futures::MapErr<Server<AddrIncoming, NewProxyService>, _> =
        server.map_err(|e| {
            error!("main() server error: {}", e);
        });

    hyper::rt::run(server_map_err);
}


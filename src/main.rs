#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate log;

use crc::crc32;
use rand::{self, RngCore};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use tokio::prelude::{future, Future, Stream};
use tokio::runtime::current_thread::{self, Runtime};

/// Nodee info to connect to each other.
#[derive(Debug, Clone, PartialEq)]
struct NodeInfo {
    addr: SocketAddr,
    cert: Vec<u8>,
}

struct NodeContext {
    received_msg: usize,
    /// nodes we are supposed to connect and exchange data with
    expected_connections: usize,
}

struct Node {
    endpoint: quinn::Endpoint,
    addr: SocketAddr,
    our_cert: Vec<u8>,
}

fn main() {
    let node_count = 15;

    let mut runtime = unwrap!(Runtime::new());

    let all_nodes: Vec<_> = (0..node_count)
        .into_iter()
        .map(|_| Node::new(&mut runtime, node_count - 1))
        .collect();
    let all_contacts = all_nodes.iter().map(|node| node.conn_info()).collect();

    for ref mut node in all_nodes {
        node.send_to_all(&all_contacts, &mut runtime);
    }

    let _ = runtime.block_on(future::empty::<(), ()>());
}

impl Node {
    /// Constructs a node ant spawns its listener.
    fn new(runtime: &mut Runtime, expected_connections: usize) -> Self {
        let (cfg, our_cert) = configure_listener();
        let mut ep_builder = quinn::Endpoint::new();
        ep_builder.listen(cfg);
        let (endpoint, driver, incoming_conns) = unwrap!(ep_builder.bind(&("127.0.0.1", 0)));
        runtime.spawn(driver.map_err(|e| panic!("Listener IO error: {}", e)));

        let ctx = Rc::new(RefCell::new(NodeContext {
            received_msg: 0,
            expected_connections,
        }));

        let task = incoming_conns
            .map_err(|()| println!("ERROR: Listener errored out"))
            .for_each(move |new_conn| {
                let conn = new_conn.connection;
                let peer_addr = conn.remote_address();
                debug!(
                    "[listener] incoming connection: id={} addr={}",
                    conn.remote_id(),
                    peer_addr
                );

                let ctx = ctx.clone();
                let task = new_conn
                    .incoming
                    .map_err(move |e| {
                        debug!(
                            "Incoming-streams from peer {} closed due to: {:?}",
                            peer_addr, e
                        );
                    })
                    .for_each(move |stream| {
                        read_from_peer(stream, ctx.clone());
                        Ok(())
                    })
                    .then(move |_| Ok(()));
                current_thread::spawn(task);

                Ok(())
            });
        runtime.spawn(task);

        let addr = unwrap!(endpoint.local_addr());
        Self {
            endpoint,
            addr,
            our_cert,
        }
    }

    fn send_to_all(&mut self, nodes: &Vec<NodeInfo>, runtime: &mut Runtime) {
        let data = random_data_with_hash(1024 * 1024);

        let self_info = self.conn_info();
        for node in nodes {
            if node != &self_info {
                self.send_data_to(node, data.clone(), runtime);
            }
        }
    }

    fn send_data_to(&mut self, node: &NodeInfo, data: Vec<u8>, runtime: &mut Runtime) {
        let client_cfg = configure_connector(&node);

        let task = unwrap!(self.endpoint.connect_with(&client_cfg, &node.addr, "Test"))
            .map_err(|e| panic!("Connection failed: {}", e))
            .and_then(|new_conn| {
                let conn = new_conn.connection;
                println!(
                    "[client] connected: id={}, addr={}",
                    conn.remote_id(),
                    conn.remote_address()
                );
                write_to_peer_connection(&conn, data);
                Ok(())
            });
        runtime.spawn(task);
    }

    fn conn_info(&self) -> NodeInfo {
        NodeInfo {
            addr: self.addr,
            cert: self.our_cert.clone(),
        }
    }
}

fn read_from_peer(stream: quinn::NewStream, ctx: Rc<RefCell<NodeContext>>) {
    let stream = match stream {
        quinn::NewStream::Bi(_bi) => panic!("Unexpected bidirectional stream here"),
        quinn::NewStream::Uni(uni) => uni,
    };

    let task = quinn::read_to_end(stream, 1024 * 1024 * 500)
        .map_err(|e| panic!("read_to_end() failed: {}", e))
        .and_then(move |(_stream, data)| {
            assert!(hash_correct(&data));
            ctx.borrow_mut().received_msg += 1;

            if ctx.borrow().received_msg == ctx.borrow().expected_connections {
                println!("Done. All checks passed");
            }
            Ok(())
        })
        .then(|_| Ok(()));
    current_thread::spawn(task);
}

fn write_to_peer_connection(conn: &quinn::Connection, data: Vec<u8>) {
    let task = conn
        .open_uni()
        .map_err(|e| panic!("Failed to open unidirection stream: {}", e))
        .and_then(move |o_stream| {
            tokio::io::write_all(o_stream, data).map_err(|e| panic!("write_all() failed: {}", e))
        })
        .and_then(move |(o_stream, _)| {
            tokio::io::shutdown(o_stream).map_err(|e| panic!("shutdown() failed: {}", e))
        })
        .map(|_| ());
    current_thread::spawn(task);
}

fn configure_connector(node: &NodeInfo) -> quinn::ClientConfig {
    let mut peer_cfg_builder = quinn::ClientConfigBuilder::new();
    let their_cert = unwrap!(quinn::Certificate::from_der(&node.cert));
    unwrap!(peer_cfg_builder.add_certificate_authority(their_cert));
    let mut peer_cfg = peer_cfg_builder.build();
    let transport_config = unwrap!(Arc::get_mut(&mut peer_cfg.transport));
    transport_config.idle_timeout = 10;
    transport_config.keep_alive_interval = 30;

    peer_cfg
}

fn configure_listener() -> (quinn::ServerConfig, Vec<u8>) {
    let (our_cert_der, our_priv_key) = gen_cert();
    let our_cert = unwrap!(quinn::Certificate::from_der(&our_cert_der));

    let our_cfg = Default::default();
    let mut our_cfg_builder = quinn::ServerConfigBuilder::new(our_cfg);
    unwrap!(our_cfg_builder.certificate(
        quinn::CertificateChain::from_certs(vec![our_cert]),
        our_priv_key
    ));
    let mut our_cfg = our_cfg_builder.build();
    let transport_config = unwrap!(Arc::get_mut(&mut our_cfg.transport_config));
    transport_config.idle_timeout = 30;
    transport_config.keep_alive_interval = 10;

    (our_cfg, our_cert_der)
}

fn gen_cert() -> (Vec<u8>, quinn::PrivateKey) {
    let cert = rcgen::generate_simple_self_signed(vec!["Test".to_string()]);
    let key = unwrap!(quinn::PrivateKey::from_der(
        &cert.serialize_private_key_der()
    ));
    (cert.serialize_der(), key)
}

fn random_data_with_hash(size: usize) -> Vec<u8> {
    let mut data = random_vec(size + 4);
    let hash = crc32::checksum_ieee(&data[4..]);
    // write hash in big endian
    data[0] = (hash >> 24) as u8;
    data[1] = ((hash >> 16) & 0xff) as u8;
    data[2] = ((hash >> 8) & 0xff) as u8;
    data[3] = (hash & 0xff) as u8;
    data
}

fn hash_correct(data: &[u8]) -> bool {
    let encoded_hash = ((data[0] as u32) << 24)
        | ((data[1] as u32) << 16)
        | ((data[2] as u32) << 8)
        | data[3] as u32;
    let actual_hash = crc32::checksum_ieee(&data[4..]);
    encoded_hash == actual_hash
}

#[allow(unsafe_code)]
fn random_vec(size: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(size);
    unsafe { ret.set_len(size) };
    rand::thread_rng().fill_bytes(&mut ret[..]);
    ret
}

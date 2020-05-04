
use futures::io;
use futures::prelude::*;
use log::{ debug, warn, info };
use smol::{ Async, Task, Timer };
use snow::{params::NoiseParams, Builder, TransportState};
use std::env;
use std::net::{ TcpListener, TcpStream };
use std::result::Result;
use std::time::Duration;
use std::net::SocketAddr;

struct NoiseConfig {
    params: NoiseParams,
    secret: Vec<u8>,
}

#[derive(Debug)]
enum Error {
    Snow(snow::Error),
    Io(io::Error),
}

impl From<snow::Error> for Error {
    fn from(err: snow::Error) -> Self {
        Error::Snow(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

async fn heartbeat(peer_addr: SocketAddr, mut noise: TransportState, mut stream: Async<TcpStream>) -> Result<(), Error> {
    let mut buf = vec![0u8; 65535];
    loop {
        let len = noise.write_message(b"heartbeat", &mut buf)?;
        println!("{} - sending heartbeat {}", peer_addr, len);
        send(&mut stream, &buf[..len]).await?;
        Timer::after(Duration::from_secs(15)).await;
        // writer(s)(&mut stream, "heartbeat\r\n").await?
    }
}

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
async fn recv(stream: &mut Async<TcpStream>) -> io::Result<Vec<u8>> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf).await?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..]).await?;
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
async fn send(stream: &mut Async<TcpStream>, buf: &[u8]) -> Result<(), Error> {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    stream.write_all(&msg_len_buf).await?;
    stream.write_all(buf).await?;
    Ok(())
}

async fn noise_server_init(cfg: &NoiseConfig,
                           stream: &mut Async<TcpStream>) -> Result<TransportState, Error> {
    let mut buf = vec![0u8; 65535];
    let builder: Builder<'_> = Builder::new(cfg.params.clone());
    let static_key = builder.generate_keypair()?.private;
    let mut noise =
        builder.local_private_key(&static_key).psk(3, &cfg.secret).build_responder()?;

    // <- e
    noise.read_message(&recv(stream).await?, &mut buf)?;

    // -> e, ee, s, es
    let len = noise.write_message(&[0u8; 0], &mut buf)?;
    send(stream, &buf[..len]).await?;

    // <- s, se
    noise.read_message(&recv(stream).await?, &mut buf)?;

    // Transition the state machine into transport mode now that the handshake is complete.
    let noise = noise.into_transport_mode()?;

    Ok(noise)
}

async fn noise_client_init(cfg: &NoiseConfig,
                           stream: &mut Async<TcpStream>) -> Result<TransportState, Error>
{
    let mut buf = vec![0u8; 65535];
    let builder: Builder<'_> = Builder::new(cfg.params.clone());
    let static_key = builder.generate_keypair()?.private;
    let mut noise =
        builder.local_private_key(&static_key).psk(3, &cfg.secret).build_initiator()?;

    // -> e
    let len = noise.write_message(&[], &mut buf)?;
    send(stream, &buf[..len]).await?;

    // <- e, ee, s, es
    noise.read_message(&recv(stream).await?, &mut buf)?;

    // -> s, se
    let len = noise.write_message(&[], &mut buf)?;
    send(stream, &buf[..len]).await?;

    let noise = noise.into_transport_mode()?;
    println!("noise protocol session established...");

    // Get to the important business of sending secured data.
    // for _ in 0..10 {
    //     let len = noise.write_message(b"HACK THE PLANET", &mut buf)?;
    //     send(stream, &buf[..len]).await?;
    // }
    // println!("notified server of intent to hack planet.");
    Ok(noise)
}

fn run_server(cfg: &NoiseConfig) -> std::io::Result<()> {
    smol::run(async {
        let listener = Async::<TcpListener>::bind("0.0.0.0:7656")?;
        println!("Listening on {}", listener.get_ref().local_addr()?);
        loop {
            println!("waiting for clients...");
            let (mut stream, peer_addr) = listener.accept().await?;
            println!("Accepted client: {}", peer_addr);

            let mnoise = noise_server_init(&cfg, &mut stream).await;
            println!("{} - noise init done", peer_addr);
            match mnoise {
                Err(err) => {
                    println!("{} - client connect err: {:?}", peer_addr, err);
                },
                Ok(noise) => {
                    println!("spawning heartbeat...");
                    Task::spawn(heartbeat(peer_addr, noise, stream)).unwrap().detach();
                    println!("done spawning");
                },
            }

            // Spawn a task that echoes messages from the client back to it.
        }
    })
}

async fn handle_server_messages(mut noise: TransportState,
                                stream: &mut Async<TcpStream>) -> Result<(), Error>
{
    let mut buf = vec![0u8; 65535];

    loop {
        let len = noise.read_message(&recv(stream).await?, &mut buf)?;
        println!("recv {} {}", len, String::from_utf8_lossy(&buf[..len]))
    }
}

fn run_client(cfg: &NoiseConfig) -> Result<(), Error> {
    smol::run(async {
        // Connect to our server, which is hopefully listening.
        let server_addr = "127.0.0.1:7656";
        let mut stream = Async::<TcpStream>::connect(server_addr).await?;
        println!("connected...");
        let mnoise = noise_client_init(&cfg, &mut stream).await;

        match mnoise {
            Err(err) => {
                println!("server connect err: {:?}", err);
            },
            Ok(noise) => {
                println!("handling server messages");
                handle_server_messages(noise, &mut stream).await?;
            },
        }

        Ok(())
    })
}

fn main() {
    env_logger::init();

    let params: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse().unwrap();
    let secret = b"i don't care for fidget spinners".to_vec();
    let cfg = NoiseConfig{ params, secret };

    for argument in env::args() {
        if argument == "--server" {
            run_server(&cfg);
            return;
        }
        else if argument == "--client" {
            run_client(&cfg);
        }
    }
}



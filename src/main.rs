mod base64;
mod sha1;

use base64::Base64;
use sha1::Sha1;

use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::str;
use std::thread;
use std::time::Duration;

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(_) => {
            let request = str::from_utf8(&buffer).unwrap();
            if request.starts_with("GET") {
                let response = handle_websocket_handshake(request);
                stream.write(response.as_bytes()).unwrap();
                stream.flush().unwrap();

                // Upgrade to WebSocket complete; enter frame handling loop
                handle_websocket_communication(stream);
            }
        }
        Err(e) => println!("Failed to receive data: {}", e),
    }
}

fn handle_websocket_handshake(request: &str) -> String {
    let mut base64 = Base64::new();
    let mut sha1 = Sha1::new();

    let key_header = "Sec-WebSocket-Key: ";
    let key = request
        .lines()
        .find(|line| line.starts_with(key_header))
        .map(|line| line[key_header.len()..].trim())
        .unwrap();

    let response_key = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    println!("{:?}", response_key);
    let hash = sha1.hash(response_key);
    println!("{:?}", hash);
    let key = base64.encode(hash).unwrap();
    println!("KEY:{}", key);

    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: {}\r\n\r\n",
        key
    )
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    println!("Server listening on port 8080");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| handle_client(stream));
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_websocket_communication(mut stream: TcpStream) {
    let mut buffer = [0; 2048];
    let mut last_ping = std::time::Instant::now();

    loop {
        if last_ping.elapsed() > Duration::from_secs(5) {
            if let Err(_) = send_ping(&mut stream) {
                println!("Ping failed; disconnecting client.");
                break;
            }
            last_ping = std::time::Instant::now();
        }

        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                match parse_frame(&buffer[..n]) {
                    Ok(Frame::Pong) => {
                        println!("Pong received");
                        continue; // Continue listening for frames
                    }
                    Ok(Frame::Ping) => {
                        if send_pong(&mut stream).is_err() {
                            println!("Failed to send pong");
                            break;
                        }
                    }
                    Ok(Frame::Close) => {
                        println!("Client initiated close");
                        break;
                    }
                    Ok(Frame::Data(data)) => {
                        println!("Received data: {}", String::from_utf8_lossy(&data));
                        // Handle data...
                    }
                    Err(e) => {
                        println!("Error parsing frame: {}", e);
                        break;
                    }
                }
            }
            Ok(_) => {} // No data read
            Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                println!("Error reading from stream: {}", e);
                break;
            }
            _ => {}
        }
    }
}

fn parse_frame(buffer: &[u8]) -> Result<Frame, &'static str> {
    if buffer.len() < 2 {
        return Err("Frame too short");
    }

    let first_byte = buffer[0];
    let fin = (first_byte & 0x80) != 0;
    let opcode = first_byte & 0x0F;
    let second_byte = buffer[1];
    let masked = (second_byte & 0x80) != 0;
    let mut payload_len = (second_byte & 0x7F) as usize;

    if !masked {
        return Err("Frames from client must be masked");
    }

    let mut offset = 2;
    if payload_len == 126 {
        if buffer.len() < 4 {
            return Err("Frame too short for extended payload length");
        }
        payload_len = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) as usize;
        offset += 2;
    } else if payload_len == 127 {
        return Err("Extended payload length too large");
    }

    if buffer.len() < offset + 4 + payload_len {
        return Err("Frame too short for mask and data");
    }

    let mask = &buffer[offset..offset + 4];
    offset += 4;

    let mut data = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        data.push(buffer[offset + i] ^ mask[i % 4]);
    }

    Ok(match opcode {
        0x01 => Frame::Data(data), // text frame
        0x02 => Frame::Data(data), // binary frame
        0x08 => Frame::Close,      // close frame
        0x09 => Frame::Ping,       // ping frame
        0x0A => Frame::Pong,       // pong frame
        _ => return Err("Unknown opcode"),
    })
}

fn send_ping(stream: &mut TcpStream) -> io::Result<usize> {
    stream.write(&[0x89, 0x00]) // Opcode for ping is 0x9 and FIN set
}

fn send_pong(stream: &mut TcpStream) -> io::Result<usize> {
    stream.write(&[0x8A, 0x00]) // Opcode for pong is 0xA and FIN set
}

enum Frame {
    Data(Vec<u8>),
    Ping,
    Pong,
    Close,
}

// use std::io::{Read, Write};
// use std::net::{TcpListener, TcpStream};
// use std::thread;
// use std::time::{Duration, Instant};

// fn main() {
//     let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind address");

//     for stream in listener.incoming() {
//         match stream {
//             Ok(stream) => {
//                 thread::spawn(|| {
//                     handle_client(stream);
//                 });
//             }
//             Err(e) => {
//                 eprintln!("Error: {}", e);
//             }
//         }
//     }
// }

// fn handle_client(mut stream: TcpStream) {
//     // Perform WebSocket handshake
//     let mut headers = [0; 1024];
//     stream.read(&mut headers).expect("Failed to read headers");

//     // Parse headers and validate WebSocket handshake
//     // Assuming that the handshake is successful for brevity

//     // Send WebSocket handshake response
//     let response = "HTTP/1.1 101 Switching Protocols\r\n\
//                     Connection: Upgrade\r\n\
//                     Upgrade: websocket\r\n\
//                     Sec-WebSocket-Accept: SomeKey\r\n\r\n";
//     stream
//         .write(response.as_bytes())
//         .expect("Failed to send handshake response");

//     // Ping the client every 5 seconds
//     let mut last_ping_time = Instant::now();
//     let mut buf = [0; 128];
//     loop {
//         let mut ping_interval = Duration::from_secs(5);
//         let elapsed = last_ping_time.elapsed();
//         if elapsed < ping_interval {
//             ping_interval -= elapsed;
//         } else {
//             // Send ping
//             let ping_frame = [0x89, 0];
//             stream.write(&ping_frame).expect("Failed to send ping");

//             // Reset ping timer
//             last_ping_time = Instant::now();

//             // Wait for pong response
//             stream
//                 .set_read_timeout(Some(ping_interval))
//                 .expect("Failed to set read timeout");
//             let bytes_read = stream.read(&mut buf).expect("Failed to read pong response");
//             if bytes_read == 0 {
//                 println!("Client disconnected or timeout reached");
//                 break;
//             }
//         }
//     }
// }

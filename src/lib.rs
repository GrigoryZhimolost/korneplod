/*
Korneplod
Copyright (C) 2025 grygory zhimolost'

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.*/

/*!
# What is this
This library is for transfering encrypted data through TCP/IP, just for this. It uses ml-kem and ChaCha20 to encrypt data, so you don't have to worry about your data's safety.

# Features
* data's encrypted with ChaCha20
* key and nonce exchange is proceeded with ml-kem in 1024-bit mode
* it's completely asynchronous

Some features(e.g. refusing/accepting connections based on channels) will be added in further versions.

# How to use this
Here are basic usage examples below:

server
``` rust
use korneplod::server::Server;
use korneplod::tools::sockaddr_from;
use korneplod::Message;
//Binding server
let mut server = Server::new( sockaddr_from("127.0.0.1", 1448, false).unwrap() ).await?;

//listening and handshaking an incoming connection
let mut client = server.listen_handshaked(true, Some([78u8; 32])).await.unwrap();

//Creating a message to send
let message = Message::new("new message".as_bytes().to_vec(), 0);

//Sending the message
client.send_message(&message).await?;
```

client
``` rust
use korneplod::client::Client;
use korneplod::tools::sockaddr_from;

//Connecting to listener
let mut client = Client::connect( sockaddr_from("127.0.0.1", 1448, false).unwrap() ).await?;

//Performing handshaking
client.handshake(Some([78u8; 32])).await?;

//Getting a message
let message = client.get_message().await?;

assert_eq!(String::from_utf8(message.get_content_vec()).unwrap(), "new message");
```*/
pub mod message;
pub mod kem;
pub mod server;
pub mod client;

pub use message::*;

use chacha20::cipher::KeyIvInit;



pub trait Party{
	fn get_message(&mut self) -> impl std::future::Future<Output = std::io::Result<Message>> + Send;
	fn send_message(&mut self, mes: &Message) -> impl std::future::Future<Output = std::io::Result<()>> + Send;
	fn get_message_with_timeout(&mut self, timeout: std::time::Duration) -> impl std::future::Future<Output = std::io::Result<Message>> + Send;
	fn send_message_with_timeout(&mut self, mes: &Message, timeout: std::time::Duration) -> impl std::future::Future<Output = std::io::Result<()>> + Send;
}

///Returns chacha20 cipher with [0u8; 32] key and [0u8; 12] nonce
#[inline]
pub fn default_chacha20_cipher() -> chacha20::ChaCha20 {
	chacha20::ChaCha20::new(&[0u8; 32].into(), &[0u8; 12].into())
}

pub mod tools {
	#[inline]
	pub fn derive_nonce(data: &[u8; 32]) -> [u8; 12]{
		[data[15], data[19], data[1], data[10], data[23], data[30], data[26], data[27], data[4], data[31], data[8], data[5]]
	}

	///Easier way to convert ip address and port into net::SocketAddr
	#[inline]
	pub fn sockaddr_from(addr: &str, port: u16, is_ipv6: bool) -> Option<std::net::SocketAddr>{
		Some(match is_ipv6{
			true =>  {
				let adr = addr.parse();

				if adr.is_err(){
					return None;
				}

				std::net::SocketAddr::new(std::net::IpAddr::V4(adr.unwrap()), port)
			},
			false => {
				let adr = addr.parse();

				if adr.is_err(){
					return None;
				}

				std::net::SocketAddr::new(std::net::IpAddr::V6(adr.unwrap()), port)
			}
		})
	}
}

#[cfg(test)]
mod tests{
	#[test]
	fn server_client_test(){
		use crate::{message::Message, server::Server, client::Client};
		use std::time::Duration;

		const ADDR: std::net::SocketAddr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 25687);

		let server_side = async ||{
			let mut server = Server::new(ADDR).await.unwrap();
			let client = server.listen_handshaked(true, Some([78u8; 32])).await;

			if let None = client{
				panic!("Connection failed");
			}

			let mut client = client.unwrap();
			let _ = client.send_message(Message::new("i am dungeon master".as_bytes().to_vec(), 56)).await;
			let message = client.get_message_with_timeout(Duration::from_secs(2)).await;
			assert!(message.is_ok());
			assert_eq!(String::from_utf8(message.unwrap().get_content().to_vec()).unwrap(), "ass we can");
		};

		let client_side = async ||{
			let mut client = Client::connect(ADDR, None).await.unwrap();
			let _ = client.handshake(Some([78u8; 32])).await.unwrap();
			let mes = client.get_message_with_timeout(Duration::from_secs(2)).await.unwrap();

			assert_eq!(String::from_utf8(mes.get_content().to_vec()).unwrap(), "i am dungeon master");

			client.send_message(Message::new("ass we can".as_bytes().to_vec(), 0)).await.unwrap();
		};

		let h1 = std::thread::spawn(move ||{
			futures::executor::block_on(server_side());
		});

		let h2 = std::thread::spawn(move ||{
			futures::executor::block_on(client_side());
		});

		let _ = h1.join();
		let _ = h2.join();
	}
}
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
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use crate::client;
use async_net::TcpListener;
use std::io;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use futures_lite::prelude::*;

///This macro is for returning None if a given Result instance has Err variant
macro_rules! res_to_none{
	($expres:expr) => {
		if $expres.is_err(){
			return None;
		}
	};
}

///if statement is true, then if break_on_fail is true it returns None otherwise continues loop
macro_rules! continue_or_break {
	($statement:expr, $break_on_fail:expr) => {
		if $statement{
			if $break_on_fail {
				return None;
			}
			continue;
		}
	}
}

///Server aсcepts or refuses incoming connections
pub struct Server{
	listener: TcpListener
}

impl Server{
	pub async fn new(address: std::net::SocketAddr) -> io::Result<Server>{
		let listener = TcpListener::bind(address).await?;
		Ok(
			Server { listener }
		)
	}

	///just listens for incoming connections wihout any checkings and returns Client instance
	pub async fn listen(&mut self) -> client::Client{
		loop {
			let sokandaddr = self.listener.accept().await;
			
			if sokandaddr.is_err(){
				continue;
			}

			let (sock, _) = sokandaddr.unwrap();

			return client::Client::from_stream(sock, crate::default_chacha20_cipher());
		}
	}

	///Listens and handshakes incoming connections if password matches(if it is)
	pub async fn listen_handshaked(&mut self, break_on_fail: bool, password: Option<[u8; 32]>) -> Option<client::Client> {
		loop {
			let sokandaddr = self.listener.accept().await;
			
			if sokandaddr.is_err(){
				continue;
			}

			let (mut sock, _) = sokandaddr.unwrap();

			let mut check_buf = [0u8; 3];
			//1
			let _ = sock.read(&mut check_buf).await;//r1

			if !check_buf.eq(&[2u8, 2u8, 8]){///////////////
				continue;
			}

			let mut buf = [0u8; 1568];//missing nonce
			//3
			if sock.read(&mut buf).await.is_err(){//r2
				if break_on_fail{
					return None;
				}
				continue;
			}
			//4
			let mut rng = rand::thread_rng();
			let enc_key = crate::kem::enc_key_from_bytes(buf.to_vec());
			let ae = crate::kem::encapsulate(&mut rng, &enc_key);

			continue_or_break!(ae.is_none(), break_on_fail);
			let (encapsulated, key) = ae.unwrap();

			//5
			continue_or_break!(sock.write_all(&encapsulated).await.is_err(), break_on_fail);//w1
			let en = crate::kem::encapsulate(&mut rng, &enc_key);

			continue_or_break!(en.is_none(), break_on_fail);
			let (encapsulated_nonce, nonce) = en.unwrap();
			//6
			continue_or_break!(sock.write_all(&encapsulated_nonce).await.is_err(), break_on_fail);//w2
			let nonce = crate::tools::derive_nonce(&nonce);

			let cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce);
			res_to_none!(cipher);
			let mut cipher = cipher.unwrap();
			let mut check_buf =[0u8; 19];
			//7
			if sock.read(&mut check_buf).await.is_err() {//r3
				if break_on_fail{
					return None;
				}
				continue;
			}
			let check_buf_copy = check_buf;
			cipher.apply_keystream(&mut check_buf);
			//8
			continue_or_break!(!(check_buf[0] == 2 && check_buf[1] == 2 && check_buf[2] == 8), break_on_fail);
			res_to_none!(sock.write_all(&check_buf_copy).await);//w3

			if password.is_none(){
				let cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce);
				res_to_none!(cipher);
				let cipher = cipher.unwrap();
				return Some(client::Client::from_stream(sock, cipher));
			}

			let mut password_buf = [0u8; 32];
			continue_or_break!(sock.read(&mut password_buf).await.is_err(), break_on_fail);//r4
			
			cipher.apply_keystream(&mut password_buf);
//maybe here

			continue_or_break!(password_buf != password.unwrap(), break_on_fail);

			//9
			let cipher = chacha20::ChaCha20::new_from_slices(&key, &buf[ buf.len() - 12..buf.len() ]);
			res_to_none!(cipher);

			let cipher = cipher.unwrap();
			res_to_none!(sock.write_all(&password_buf).await);//w4

			return Some(client::Client::from_stream(sock, cipher));
		}
	}	
}

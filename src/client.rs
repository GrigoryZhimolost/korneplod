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

use crate::kem;
use crate::Message;

use std::io;
use std::io::{Error, ErrorKind};

use async_net::TcpStream;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use futures_lite::{AsyncReadExt, AsyncWriteExt};

pub struct Client{
	stream: TcpStream,
	cipher: ChaCha20,
	cipher_backup: ChaCha20
}

impl Client {
	pub async fn connect(addr: std::net::SocketAddr, cipher: Option<ChaCha20>) -> io::Result<Client> {
		let cipher = cipher.unwrap_or(crate::default_chacha20_cipher());

		Ok(Client{
			stream: TcpStream::connect(addr).await?,
			cipher_backup: cipher.clone(),
			cipher,
		})
	}

	pub fn from_stream(stream: TcpStream, cipher: ChaCha20) -> Client {
		Client{ stream, cipher_backup: cipher.clone(), cipher }
	}

	///Performes hadshaking and thus prepares a `Client` instance for message transmission. Use this function only if the Client instance is created with `connect` method
	pub async fn handshake(&mut self, password: Option<[u8; 32]>) -> io::Result<()> {
		self.stream.write_all(&[2u8, 2u8, 8u8]).await?;//w1

		let mut rng = rand::thread_rng();

		let (dk, ek) = kem::create_keypair(&mut rng);
		let ek_bytes = kem::enc_key_to_bytes(&ek);

		self.stream.write_all(&ek_bytes[..]).await?;//w2

		let mut ek_bytes = [0u8; 1568];
		self.stream.read(&mut ek_bytes).await?;//r1

		let mut random_bytes: [u8; 16] = [0u8; 16];

		for i in 0..16usize {
			random_bytes[i] = rand::random::<u8>();
		}
		let mut random_bytes: Vec<u8> = random_bytes.to_vec();

		let mut chph_ = vec![2u8, 2u8, 8u8];
		chph_.append(&mut random_bytes);
		let mut chph: [u8; 19] = [0u8; 19];

		for (ind, i) in chph_.into_iter().enumerate(){
			chph[ind] = i;
		}

		let decapsulated_key: Option<[u8; 32]> = kem::decapsulate(&ek_bytes, &dk);

		if let None = decapsulated_key {
			return Err(Error::new(ErrorKind::InvalidData, "Cannot decapsulate encapsulated key"));
		}

		let decapsulated_key: [u8; 32] = decapsulated_key.unwrap();

		self.stream.read(&mut ek_bytes).await?;//r2

		let decapsulated: Option<[u8; 32]> = kem::decapsulate(&ek_bytes, &dk);

		if let None = decapsulated {
			return Err(Error::new(ErrorKind::InvalidData, "Cannot decapsulate encapsulated nonce"));
		}

		let nonce: [u8; 12] = crate::tools::derive_nonce(&decapsulated.unwrap());
		let mut cipher = chacha20::ChaCha20::new(&decapsulated_key.into(), &nonce.into());
		cipher.apply_keystream(&mut chph);

		let cph = chph.clone();

		self.stream.write_all(&chph).await?;//w3
		self.stream.read(&mut chph).await?;//r3

		if cph != chph {
			return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, format!("the server's answer doesn't match the sent data. Expected: {:?}, have: {:?}", cph, chph)));
		}

		if password.is_none(){
			self . cipher = chacha20::ChaCha20::new(&decapsulated_key.into(), &nonce.into());
			return Ok(());
		}

		let mut password = password.unwrap();
		self.cipher.apply_keystream(&mut password);

		self.stream.write_all(&password).await?;//w4
		self.stream.read(&mut password).await?;//r4

		self.cipher = chacha20::ChaCha20::new(&decapsulated_key.into(), &nonce.into());
		return Ok(());

	}

	#[inline]
	pub async fn send_message(&mut self, mes: crate::Message) -> io::Result<()> {
		let mut mib = mes.as_bytes_once();
		self.cipher.apply_keystream(&mut mib);
		let data_size: [u8; 8] = (mib.len() as u64).to_be_bytes();

		if let Err(e) = self.stream.write_all(&data_size).await{
			self.cipher = self.cipher_backup.clone();
			return Err(e);
		}

		let mut buf: [u8; 1024] = [0u8; 1024];

		if mib.len() >= 1024{
			for i in 0.. mib.len() >> 10{
				for (data_ind, buf_ind) in (1024 * i .. 1024 * (i + 1)).zip( 0..1024usize ) {
					buf[buf_ind] = mib[data_ind];
				}

				if let Err(e) = self.stream.write_all(&buf).await {
					self.cipher = self.cipher_backup.clone();
					return Err(e);
				}
			}
		}

		if mib.len() != 1024 {
			let remaining = mib.len() % 1024;
			for (data_ind, buf_ind) in (mib.len() - remaining .. mib.len()).zip(0..remaining){
				buf[buf_ind] = mib[data_ind];
			}
	
			if let Err(e) = self.stream.write_all(&buf).await{
				self.cipher = self.cipher_backup.clone();
				return Err(e);
			}
		}

		self.cipher_backup = self.cipher.clone();

		Ok(())
	}

	#[inline]
	pub async fn get_message(&mut self) -> io::Result<Message> {
		let mut buf = [0u8; 1024];
		let mut data_size = [0u8; 8];

		self.stream.read(&mut data_size).await?;

		let data_size = u64::from_be_bytes(data_size);
		let mut raw_message: Vec<u8> = Vec::new();

		if data_size >= 1024{
			for _ in 0..data_size >> 10{
				self.stream.read(&mut buf).await?;
				for ind in 0..1024usize{
					raw_message.push(buf[ind]);
				}
			}
		}

		if data_size != 1024{
			self.stream.read(&mut buf).await?;

			for ind in 0..data_size % 1024 {
				raw_message.push(buf[ind as usize]);
				
			}
		}

		self.cipher.apply_keystream(&mut raw_message);
		self.cipher_backup = self.cipher.clone();

		let mes = crate::message::Message::from_bytes(&raw_message[..]);

		Ok(mes)
	}

	#[inline]
	pub async fn send_message_with_timeout(&mut self, mes: crate::Message, timeout: std::time::Duration) -> io::Result<()> {
		let res = async_std::future::timeout(timeout, self.send_message(mes)).await;
		if res.is_err(){
			return Err(Error::new(ErrorKind::TimedOut,  "time's up"))
		}

		res.unwrap()
	}

	//#[inline]
	pub async fn get_message_with_timeout(&mut self, timeout: std::time::Duration) -> io::Result<Message> {
		let res = async_std::future::timeout(timeout, self.get_message()).await;
		if res.is_err(){
			return Err(Error::new(ErrorKind::TimedOut, "time's up"))
		}

		res.unwrap()
	}
}
/*Korneplod
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
#[derive(Clone)]
pub struct Message{
	content: Vec<u8>,
	code: u8
}

impl Message{
	///Creates a new `Message` instance with auto-computed checksum
	#[inline]
	pub fn new(content: Vec<u8>, code: u8) -> Message {
		Message{ content, code }
	}

	#[inline]
	pub fn get_content(&self) -> &[u8]{
		&self.content[..]
	}

	#[inline]
	pub fn get_content_vec(&self) -> Vec<u8>{
		self.content.clone()
	}

	#[inline]
	pub fn get_code(&self) -> u8{
		self.code
	}

	#[inline]
	pub fn as_bytes(&self) -> Vec<u8> {
		vec![vec![self.code], self.content.clone()].concat()
	}

	#[inline]
	pub fn as_bytes_once(self) -> Vec<u8> {
		vec![vec![self.code], self.content].concat()
	}

	///The same as `load` method, but from bytes
	#[inline]
	pub fn from_bytes(bytes: &[u8]) -> Message {
		Message {
			content: bytes[1..].to_vec(), 
			code: bytes[0]
		}
	}
}

#[cfg(test)]
mod tests{
	use super::*;
	#[test]
	fn ser_de_test(){
		let message = Message::new("78".as_bytes().to_vec(), 78);
		let msg = Message::from_bytes(&message.as_bytes()[..]);

		assert_eq!(msg.get_code(), message.get_code());
		assert_eq!(msg.get_content(), message.get_content());
	}
}
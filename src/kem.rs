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

use ml_kem::MlKem1024;
use ml_kem::KemCore;
use ml_kem::kem::Decapsulate;
use ml_kem::kem::Encapsulate;
use ml_kem::MlKem1024Params;
use ml_kem::EncodedSizeUser;

use rand_core::{RngCore, CryptoRng};

///Creates ml-kem(kyber)1024 keypair 
#[inline]
pub fn create_keypair<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(ml_kem::kem::DecapsulationKey<MlKem1024Params>, 
	ml_kem::kem::EncapsulationKey<MlKem1024Params>) 
	where CryptoRngCore: RngCore + CryptoRng {
	MlKem1024::generate(rng)
}

///Serializes ml-kem encapsulation key into bytes
#[inline]
pub fn enc_key_to_bytes(key: &ml_kem::kem::EncapsulationKey<MlKem1024Params>) -> Vec<u8> {
	key.as_bytes().to_vec()
}

///restores encapsulation key from bytes
#[inline]
pub fn enc_key_from_bytes(key: Vec<u8>) -> ml_kem::kem::EncapsulationKey<MlKem1024Params> {
	let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem1024Params>> = ml_kem::array::Array::try_from_iter(key.into_iter()).unwrap(); 

	ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation)
}

///Encapsulates a random 256 bit key with the given enc key. Returns encapsulated and untouched key as tuple inside Option
#[inline]
pub fn encapsulate <CryptoRngCore>(rng: &mut CryptoRngCore, ek: &ml_kem::kem::EncapsulationKey<MlKem1024Params>) ->
	Option<([u8; 1568], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
	let mr = ek.encapsulate(rng);

	if mr.is_err(){
		return None;
	}

	let (en, ss) = mr.unwrap();

	let mut rss = [0u8; 32];
	for (ind, i) in ss.as_slice().iter().enumerate(){
		rss[ind] = *i;
	}

	let mut r = [0u8; 1568];
	for (ind, i) in en.as_slice().iter().enumerate(){
		r[ind] = *i;
	}

	Some((r, rss))
}

///Decapsulates encapsulated key
pub fn decapsulate(data: &[u8; 1568], dk: &ml_kem::kem::DecapsulationKey<MlKem1024Params>) ->
	Option<[u8; 32]> {
	use ml_kem::array::typenum;

	let ta: Result<ml_kem::array::Array<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

	if let Err(_) = ta {
		return None;
	}

	let ta  = ta.unwrap();
	let key = dk.decapsulate(&ta);

	if key.is_err() {
		return None;
	}
	let key = key.unwrap();
	let key: &[u8] = key.as_slice();

	assert_eq!(key.len(), 32);
	let mut res = [0u8; 32];

	for (ind, i) in key.into_iter().enumerate(){
		res[ind] = *i;
	}

	Some(res)
}

#[cfg(test)]
mod tests{
	#[test]
	fn works_fine(){
		use super::*;

		let mut rng = rand::thread_rng();

		let (dk, ek) = create_keypair(&mut rng);
		let r = enc_key_to_bytes(&ek);
		assert_eq!(r.len(), 228);
		let ek = enc_key_from_bytes(r);

		let (enc, key) = encapsulate(&mut rng, &ek).unwrap();
		let second_key = decapsulate(&enc, &dk).unwrap();

		assert_eq!(key, second_key);

	}
}
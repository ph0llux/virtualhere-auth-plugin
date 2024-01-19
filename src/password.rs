// - STD
use std::error::Error;

// - external
use argon2::{self, Config, Variant, Version};
use md5;
use log::debug;

pub(crate) fn verify_password_hash(old_pw_hash: &str, password: &str) -> Result<bool, Box<dyn Error>> {
    Ok(argon2::verify_encoded(old_pw_hash, password.as_bytes())?)
}

pub(crate) fn hash_password_argon2(password: &str, salt: &[u8], mem_cost: u32, lanes: u32, iterations: u32, hash_length: u32) -> Result<String, Box<dyn Error>> {
	let hash = md5::compute(password);
	let encoded_hash = format!("{:x}", hash);
	debug!("password: \"{password}\" encoded to md5 hash: {encoded_hash}");

	let config = Config {
	    variant: Variant::Argon2id,
	    version: Version::Version13,
	    mem_cost,
	    time_cost: iterations,
	    lanes,
	    secret: &[],
	    ad: &[],
	    hash_length
	};
    Ok(argon2::hash_encoded(encoded_hash.as_bytes(), salt, &config)?)
}
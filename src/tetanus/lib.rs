pub mod locators;
pub mod hooks;
pub mod tricks;

use std::{net::TcpStream, sync::Mutex};

use tracing::{info, error};

use crate::hooks::add_hooks;


#[ctor::ctor] // our entrypoint is the library constructor, invoked by dlopen
fn constructor() {
	std::thread::spawn(|| {
		match TcpStream::connect("127.0.0.1:13337") {
			Ok(stream) => tracing_subscriber::fmt()
				.with_writer(Mutex::new(stream))
				.init(),
			Err(_) => {},
		}

		info!(target: "tetanus", "infected target");

		if let Err(e) = add_hooks() {
			error!(target: "tetanus", "could not add hooks : {}", e);
		}
	});
}

#[ctor::dtor]
fn destructor() {}


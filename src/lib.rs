use std::{error::Error, ffi::c_int};

use nix::libc::{socklen_t, sockaddr};
use retour::static_detour;

static_detour! {
	static SOCKET_HOOK : unsafe extern "C" fn(i32, i32, i32) -> i32;
	static CONNECT_HOOK : unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
}

fn add_hooks() -> Result<(), Box<dyn Error>> {
	unsafe { 
		SOCKET_HOOK.initialize(nix::libc::socket, |dom, tp, proto| {
			eprintln!("caught socket({}, {}, {}) call", dom, tp, proto);
			SOCKET_HOOK.call(dom, tp, proto)
		})?;
		SOCKET_HOOK.enable()?;

		CONNECT_HOOK.initialize(nix::libc::connect, |fd, info, len| {
			eprintln!("caught connect({}, ??, {}) call", fd, len);
			CONNECT_HOOK.call(fd, info, len)
		})?;
		CONNECT_HOOK.enable()?;
	}

	Ok(())
}



#[ctor::ctor]
fn constructor() {
	println!("Infected!");

	if let Err(e) = add_hooks() {
		eprintln!("[!] Could not add hooks : {}", e);
	}
}

use std::{error::Error, ffi::c_int};

use dlopen::symbor::Library;
use nix::libc::{socklen_t, sockaddr};
use retour::static_detour;

static_detour! {
	static SOCKET_HOOK : unsafe extern "C" fn(i32, i32, i32) -> i32;
	static CONNECT_HOOK : unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
	static LOAD_EXT_HOOK : unsafe extern "C" fn(c_int) -> c_int;
}

// extern "C" {
// 	fn load_ext() -> ();
// }

fn add_hooks() -> Result<(), Box<dyn Error>> {
	let exec = Library::open_self()?;

	let load_ext_sym = unsafe { exec.symbol::<unsafe extern "C" fn(c_int) -> c_int>("load_ext") };

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

		match load_ext_sym {
			Ok(sym) => {
				LOAD_EXT_HOOK.initialize(*sym, |x| { eprintln!("intercepted load_ext!"); x })?;
				LOAD_EXT_HOOK.enable()?;
			},
			Err(e) => {
				eprintln!("[!] skipping load_ext hook : {}", e);
			},
		}
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

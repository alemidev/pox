use std::ffi::c_int;

use retour::static_detour;
use tracing::info;

use crate::locators::find_symbol;

static_detour! {
	static HOOK : unsafe extern "C" fn() -> c_int;
}

pub fn add_hooks() -> Result<(), Box<dyn std::error::Error>> {
	if let Some(ptr) = find_symbol("load_secret")? {
		unsafe {
			HOOK.initialize(ptr, cb::hook)?;
			HOOK.enable()?;
		}
		info!("installed hook on 'load_secret'");
	}

	Ok(())
}

mod cb {
	use tracing::info;

	use super::HOOK;

	pub fn hook() -> i32 {
		let secret = unsafe { HOOK.call() };
		info!("( ͡° ͜ʖ ͡°) its {}", secret);
		secret
	}
}

use std::{error::Error, ffi::c_int, path::{Path, PathBuf}};

use elf::{ElfBytes, endian::AnyEndian, ParseError};
use libloading::os::unix::{Library, Symbol};
use proc_maps::get_process_maps;
use retour::{static_detour, Function};

static_detour! {
	static HOOK : unsafe extern "C" fn() -> c_int;
}

#[ctor::ctor] // our entrypoint is the library constructor, invoked by dlopen
fn constructor() {
	std::thread::spawn(|| {
		eprint!(" -[infected]- ");

		if let Err(e) = add_hooks() {
			eprintln!("[!] Could not add hooks : {}", e);
		}
	});
}

fn add_hooks() -> Result<(), Box<dyn Error>> {
	let ptr = find_symbol("load_secret")?;

	unsafe {
		HOOK.initialize(ptr, || {
			let secret = HOOK.call();
			eprint!(" ( ͡° ͜ʖ ͡°) its {} ", secret);
			secret
		})?;
		HOOK.enable()?;
	}

	Ok(())
}

fn find_symbol<T : Function>(name: &str) -> Result<T, Box<dyn Error>> {
	// try to find it among exported symbols
	let this = Library::this(); // TODO don't reopen it every time
	let sym : Result<Symbol<T>, libloading::Error> = unsafe { this.get(name.as_bytes()) };
	if let Ok(s) = sym {
		return Ok(*s);
	}

	// try to read it from executable's elf
	if let Some(exec) = find_argv0() {
		let (base, path) = map_addr_path(&exec)?;
		let offset = offset_in_elf(&path, &name)?;
		let addr : *const () = (base + offset) as *const ();
		return Ok(unsafe { Function::from_ptr(addr) } );
	}

	Err(Box::new(not_found("could not find symbol in executable ELF, possibly stripped?")))
}

fn offset_in_elf(path: &Path, symbol: &str) -> Result<usize, ParseError> {
	let exec_data = std::fs::read(path)?;
	let headers = ElfBytes::<AnyEndian>::minimal_parse(&exec_data)?;
	let common = headers.find_common_data()?;

	// first try with hash table
	if let Some(hash_table) = common.sysv_hash {
		if let Some(dynsyms) = common.dynsyms {
			if let Some(strtab) = common.dynsyms_strs {
				if let Some((_id, sym)) = hash_table.find(symbol.as_bytes(), &dynsyms, &strtab)? {
					return Ok(sym.st_value as usize);
				}
			}
		}
	}

	// fall back to iterating symbols table
	if let Some(symtab) = common.symtab {
		if let Some(strs) = common.symtab_strs {
			for sym in symtab {
				let name = strs.get(sym.st_name as usize)?;
				if name == symbol {
					return Ok(sym.st_value as usize);
				}
			}
		}
	}

	Err(not_found("idk where to search :(").into())
}

fn map_addr_path(name: &str) -> std::io::Result<(usize, PathBuf)> {
	let proc_maps = get_process_maps(std::process::id() as i32)?;

	for map in proc_maps {
		// println!("map > 0x{:08X} {} [{:x}] - {} [{}]", map.start(), map.flags, map.offset, map.inode, _path_to_str(map.filename()));
		if map.is_exec() {
			if let Some(path) = map.filename() {
				if path.ends_with(name) {
					return Ok((map.start() - map.offset, map.filename().unwrap().to_path_buf()));
				}
			}
		}
	}

	Err(not_found("no process is mapped from a path ending with given name"))
}

fn find_argv0() -> Option<String> { // could be a relative path, just get last member
	Some(std::env::args().next()?.split("/").last()?.into()) // TODO separator for windows?
}

fn not_found(txt: &str) -> std::io::Error {
	std::io::Error::new(std::io::ErrorKind::NotFound, txt)
}

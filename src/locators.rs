use std::error::Error;

use libloading::os::unix::{Library, Symbol};
use retour::Function;

use tracing::warn;

use crate::tricks::find_argv0;


pub fn find_symbol<T : Function>(name: &str) -> Result<Option<T>, Box<dyn Error>> {
	// try to find it among exported symbols
	let this = Library::this(); // TODO don't reopen it every time
	let sym : Result<Symbol<T>, libloading::Error> = unsafe { this.get(name.as_bytes()) };
	if let Ok(s) = sym {
		return Ok(Some(*s));
	}

	// try to read it from executable's elf
	match find_argv0() {
		None => warn!("could not find argv0 for process"),
		Some(exec) => match procmaps::map_addr_path(std::process::id() as i32, &exec)? {
			None => warn!("could not find base addr of process image"),
			Some((base, path)) => match exec::offset_in_elf(&path, &name)? {
				None => warn!("could not locate requested symbol in ELF"),
				Some(offset) => {
					let addr = (base + offset) as *const ();
					return Ok(Some(unsafe { Function::from_ptr(addr) } ));
				}
			}
		}
	}

	Ok(None)
}


pub mod exec {
	use std::path::Path;

	use elf::{ParseError, ElfBytes, endian::AnyEndian};
	use tracing::{warn, debug};

	pub fn offset_in_elf(path: &Path, symbol: &str) -> Result<Option<usize>, ParseError> {
		let exec_data = std::fs::read(path)?;
		let headers = ElfBytes::<AnyEndian>::minimal_parse(&exec_data)?;
		let common = headers.find_common_data()?;
	
		// first try with hash table
		match common.sysv_hash {
			None => warn!("missing symbols hash table in ELF"),
			Some(sysv_hash) => match common.dynsyms {
				None => warn!("missing dynamic symbols in ELF"),
				Some(dynsyms) => match common.dynsyms_strs {
					None => warn!("missing string tab for dynamic symbols in ELF"),
					Some(dynsyms_strs) =>	match sysv_hash.find(symbol.as_bytes(), &dynsyms, &dynsyms_strs)? {
						None => debug!("could not find symbol {} in ELF hashmap", symbol),
						Some((_id, sym)) => return Ok(Some(sym.st_value as usize)),
					},
				},
			},
		}
	
		// fall back to iterating symbols table
		match common.symtab {
			None => warn!("missing symbols table in ELF"),
			Some(symtab) => match common.symtab_strs {
				None => warn!("missing names for symbols in ELF"),
				Some(symtab_strs) => {
					for sym in symtab {
						let name = symtab_strs.get(sym.st_name as usize)?;
						if name == symbol {
							return Ok(Some(sym.st_value as usize));
						}
					}
					debug!("no symbol matched '{}'", symbol);
				}
			}
		}
	
		Ok(None)
	}
}

pub mod procmaps {
	use std::path::PathBuf;

	use proc_maps::get_process_maps;
	use tracing::{debug, warn};

	use crate::tricks::fmt_path;

	pub fn map_addr_path(pid: i32, name: &str) -> std::io::Result<Option<(usize, PathBuf)>> {
		let proc_maps = get_process_maps(pid)?;
	
		for map in proc_maps {
			debug!("map > 0x{:08X} {} [{:x}] - {} [{}]", map.start(), map.flags, map.offset, map.inode, fmt_path(map.filename()));
			if map.is_exec() {
				if let Some(path) = map.filename() {
					if path.ends_with(name) {
						return Ok(Some((map.start() - map.offset, map.filename().unwrap().to_path_buf())));
					}
				}
			}
		}
		warn!("could not find address of '{}'", name);

		Ok(None)
	}
}

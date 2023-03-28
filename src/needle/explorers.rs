use std::{ffi::c_void, path::{Path, PathBuf}, io::{ErrorKind, Error}};

use elf::{ElfBytes, endian::AnyEndian};
use nix::{unistd::Pid, sys::{ptrace, wait::waitpid}};
use proc_maps::get_process_maps;

pub fn step_to_syscall(pid: Pid) -> nix::Result<usize> {
	let mut registers;
	let mut addr;
	let mut instructions;

	// seek to syscall
	loop {
		registers = ptrace::getregs(pid)?;
		addr = registers.rip as usize;
		instructions = ptrace::read(pid, addr as *mut c_void)?;
		// println!("@ 0x{:X} [{:x}]", insn_addr, curr_instr);

		if instructions & 0xFFFF == 0x050F {
			return Ok(addr);
		}

		ptrace::step(pid, None)?;
		waitpid(pid, None)?;
	}
}

fn _path_to_str<'a>(p: Option<&'a Path>) -> &'a str {
	match p {
		Some(path) => {
			match path.to_str() {
				Some(s) => s,
				None => "?",
			}
		},
		None => "",
	}
}

pub fn find_libc(pid: Pid) -> std::io::Result<(usize, PathBuf)> {
	let proc_maps = get_process_maps(pid.as_raw())?;

	for map in proc_maps {
		// println!("map > 0x{:08X} {} [{:x}] - {} [{}]", map.start(), map.flags, map.offset, map.inode, _path_to_str(map.filename()));
		if map.is_exec() && _path_to_str(map.filename()).contains("libc.so") {
			return Ok((
				map.start() - map.offset,
				map.filename().expect("matched empty option?").to_path_buf()
			));
		}
	}

	Err(Error::new(ErrorKind::NotFound, "no libc in target proc maps"))
}

pub fn find_dlopen(path: &Path) -> std::io::Result<usize> {
	let libc = std::fs::read(path).expect("could not read libc");
	let headers = ElfBytes::<AnyEndian>::minimal_parse(&libc).expect("failed parsing libc as ELF");
	let common = headers.find_common_data().expect("shdrs should parse");
	let dynsyms = common.dynsyms.unwrap();
	let strtab = common.dynsyms_strs.unwrap();
	let hash_table = common.sysv_hash.unwrap();
	let (_id, dlopen) = hash_table.find(b"dlopen", &dynsyms, &strtab)
		.expect("could not parse symbols hash table")
		.expect("could not find dlopen symbol");

	return Ok(dlopen.st_value as usize);
}

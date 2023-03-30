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

		if instructions & 0xFFFF == 0x050F {
			return Ok(addr);
		}

		ptrace::step(pid, None)?;
		waitpid(pid, None)?;
	}
}

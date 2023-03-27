use std::ffi::c_void;

use nix::{Result, unistd::Pid, sys::{ptrace, wait::waitpid}};

#[allow(unused)]
pub fn read_buffer(pid: Pid, addr: usize, size: usize, word: u32) -> Result<Vec<u8>> {
	let mut out = vec![];

	for i in (0..size).step_by((word/8) as usize) {
		let data = ptrace::read(pid, (addr + i) as *mut c_void)?;
		for j in 0..(word/8) as usize {
			out.push(((data >> (j * 8)) & 0xFF) as u8);
		}
	}

	Ok(out)
}

pub fn write_buffer(pid: Pid, addr: usize, payload: &[u8], word:u32) -> Result<()> {
	let step = word / 8;
	let mut at = addr;

	for chunk in payload.chunks(step as usize) {
		let mut buf : u64 = 0;
		for (i, c) in chunk.iter().enumerate() {
			buf |= (*c as u64) << (i * 8);
		}
		unsafe { ptrace::write(pid, at as *mut c_void, buf as *mut c_void)?; }
		at += step as usize;
	}

	Ok(())
}

pub fn step_to_syscall(pid: Pid) -> Result<usize> {
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

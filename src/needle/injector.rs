use std::ffi::c_void;

use nix::{Result, unistd::Pid, sys::{ptrace, wait::waitpid}};

pub trait RemoteOperation {
	fn inject(&mut self, pid: Pid, syscall: usize) -> Result<u64>;
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

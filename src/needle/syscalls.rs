use nix::{libc::user_regs_struct, Result, sys::{ptrace, wait::waitpid}, unistd::Pid};

use crate::{injector::RemoteOperation, senders::RemoteString};

pub trait RemoteSyscall {
	fn registers(&self, regs: &mut user_regs_struct);

	fn prepare_registers(regs: &mut user_regs_struct, rax: u64, rdi: u64, rsi: u64, rdx: u64, r10: u64, r8: u64, r9: u64) {
		regs.rax = rax;
		regs.rdi = rdi;
		regs.rsi = rsi;
		regs.rdx = rdx;
		regs.r10 = r10;
		regs.r8  = r8;
		regs.r9  = r9;
	}
}

impl<T> RemoteOperation for T where T: RemoteSyscall {
	fn inject(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		let mut regs = ptrace::getregs(pid)?;
		regs.rip = syscall as u64;
		self.registers(&mut regs);
		ptrace::setregs(pid, regs)?;
		ptrace::step(pid, None)?;
		waitpid(pid, None)?;
		regs = ptrace::getregs(pid)?;
		Ok(regs.rax)
	}
}

pub struct RemoteMMap {
	addr: u64,
	len: usize,
	prot: i32,
	flags: i32,
	fd: i64,
	off: u64,
}



impl RemoteMMap {
	pub fn args(addr: u64, len: usize, prot: i32, flags: i32, fd: i64, off: u64) -> Self {
		RemoteMMap { addr, len, prot, flags, fd, off }
	}
}

impl RemoteSyscall for RemoteMMap {
	fn registers(&self, regs: &mut user_regs_struct) {
		Self::prepare_registers(regs, 9, self.addr, self.len as u64, self.prot as u64, self.flags as u64, self.fd as u64, self.off);
	}
}

pub struct RemoteOpen {
	filename: RemoteString,
	flags: u64,
	mode: u64,
}

#[allow(unused)]
impl RemoteOpen {
	pub fn args(filename: RemoteString, flags: u64, mode: u64) -> Self {
		RemoteOpen { filename, flags, mode }
	}
}

impl RemoteSyscall for RemoteOpen {
	fn registers(&self, regs: &mut user_regs_struct) { // TODO handle this unwrap
		Self::prepare_registers(regs, 2, self.filename.ptr.unwrap() as u64, self.flags, self.mode, 0, 0, 0);
	}
}

pub struct RemoteWrite {
	fd: i64,
	ptr: u64,
	len: u64,
}

impl RemoteWrite {
	pub fn args(fd: i64, ptr: u64, len: u64) -> Self {
		RemoteWrite { fd, ptr, len }
	}

	pub fn string(fd: i64, txt: RemoteString) -> Self {
		RemoteWrite { fd, ptr: txt.ptr.expect("remote write with uninjected remote str") as u64, len: txt.txt.len() as u64 }
	}
}

impl RemoteSyscall for RemoteWrite {
	fn registers(&self, regs: &mut user_regs_struct) {
		Self::prepare_registers(regs, 1, self.fd as u64, self.ptr, self.len, 0, 0, 0);
	}
}

pub struct RemoteExit {
	code: i64,
}

#[allow(unused)]
impl RemoteExit {
	pub fn args(code: i64) -> Self {
		RemoteExit { code }
	}
}

impl RemoteSyscall for RemoteExit {
	fn registers(&self, regs: &mut user_regs_struct) {
	 Self::prepare_registers(regs, 60, self.code as u64, 0, 0, 0, 0, 0);
	}
}

use nix::{libc::user_regs_struct, Result, sys::{ptrace, wait::waitpid}, unistd::Pid};
use tracing::debug;

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
		let syscall_nr = regs.rax;
		ptrace::setregs(pid, regs)?;
		ptrace::step(pid, None)?;
		waitpid(pid, None)?;
		regs = ptrace::getregs(pid)?;
		debug!(target: "remote-syscall", "executed syscall #{} -> {}", syscall_nr, regs.rax);
		Ok(regs.rax)
	}

	fn revert(&mut self, _pid: Pid, _syscall: usize) -> Result<u64> { Ok(0) }
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

pub struct RemoteMUnmap {
	addr: usize,
	len: usize,
}

impl RemoteMUnmap {
	pub fn args(addr: usize, len: usize) -> Self {
		RemoteMUnmap { addr, len }
	}
}

impl RemoteSyscall for RemoteMUnmap {
	fn registers(&self, regs: &mut user_regs_struct) {
		regs.rax = 11;
		regs.rdi = self.addr as u64;
		regs.rsi = self.len as u64;
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
		regs.rax = 2;
		regs.rdi = self.filename.ptr.unwrap() as u64;
		regs.rsi = self.flags;
		regs.rdx = self.mode;
	}
}

pub struct RemoteWrite {
	fd: i64,
	ptr: u64,
	len: u64,
}

#[allow(unused)]
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
		regs.rax = 1;
		regs.rdi = self.fd as u64;
		regs.rsi = self.ptr;
		regs.rdx = self.len;
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

	/// since the exit syscall will never return, normal inject() will always return an error.
	/// calling this will just return success once the syscall has been invoked
	pub fn exit(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		let mut regs = ptrace::getregs(pid)?;
		regs.rip = syscall as u64;
		self.registers(&mut regs);
		ptrace::setregs(pid, regs)?;
		ptrace::step(pid, None)?;
		Ok(self.code as u64)
	}
}

impl RemoteSyscall for RemoteExit {
	fn registers(&self, regs: &mut user_regs_struct) {
		regs.rax = 60;
		regs.rdi = self.code as u64;
	}
}

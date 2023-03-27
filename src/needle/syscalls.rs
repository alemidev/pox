use nix::{libc::{user_regs_struct, MAP_PRIVATE, MAP_ANON, PROT_READ, PROT_WRITE}, Result, sys::{ptrace, wait::waitpid}, unistd::Pid};

use crate::operations::write_buffer;

pub struct RemoteString {
	pub ptr: usize,
	pub txt: String,
}

impl RemoteString {
	pub fn new(pid: Pid, syscall: usize, txt: String) -> Result<Self> {
		let ptr = RemoteMMap::args(
			0, txt.len(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0xFFFFFFFFFFFFFFFF, 0
		).syscall(pid, syscall)? as usize;
		write_buffer(pid, ptr, txt.as_bytes(), 32)?; // TODO don't hardcode word size
		Ok(RemoteString { ptr, txt })
	}
}

pub trait RemoteSyscall {
	fn registers(&self, regs: &mut user_regs_struct);

	fn syscall(&self, pid: Pid, addr: usize) -> Result<u64> {
		let mut regs = ptrace::getregs(pid)?;
		regs.rip = addr as u64;
		self.registers(&mut regs);
		ptrace::setregs(pid, regs)?;
		ptrace::step(pid, None)?;
		waitpid(pid, None)?;
		regs = ptrace::getregs(pid)?;
		Ok(regs.rax)
	}

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

pub struct RemoteMMap {
	addr: u64,
	len: usize,
	prot: i32,
	flags: i32,
	fd: u64,
	off: u64,
}

impl RemoteMMap {
	pub fn args(addr: u64, len: usize, prot: i32, flags: i32, fd: u64, off: u64) -> Self {
		RemoteMMap { addr, len, prot, flags, fd, off }
	}
}

impl RemoteSyscall for RemoteMMap {
	fn registers(&self, regs: &mut user_regs_struct) {
		Self::prepare_registers(regs, 9, self.addr, self.len as u64, self.prot as u64, self.flags as u64, self.fd, self.off);
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
	fn registers(&self, regs: &mut user_regs_struct) {
		Self::prepare_registers(regs, 2, self.filename.ptr as u64, self.flags, self.mode, 0, 0, 0);
	}
}

pub struct RemoteWrite {
	fd: u64,
	buf: RemoteString, // TODO make remote slice or remote bytes
}

impl RemoteWrite {
	pub fn args(fd: u64, buf: RemoteString) -> Self {
		RemoteWrite { fd, buf }
	}
}

impl RemoteSyscall for RemoteWrite {
	fn registers(&self, regs: &mut user_regs_struct) {
		Self::prepare_registers(regs, 1, self.fd, self.buf.ptr as u64, self.buf.txt.len() as u64, 0, 0, 0);
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

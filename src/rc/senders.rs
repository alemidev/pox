use std::{ffi::c_void, mem::size_of};

use nix::{Result, unistd::Pid, sys::ptrace, libc::{PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANON}};
use tracing::{debug, info};

use crate::rc::{injector::RemoteOperation, syscalls::{RemoteMMap, RemoteMUnmap}};

const WORD_SIZE : usize = size_of::<usize>();

#[allow(unused)]
pub fn read_buffer(pid: Pid, addr: usize, size: usize) -> Result<Vec<u8>> {
	let mut out = vec![];

	for i in (0..size).step_by(WORD_SIZE) {
		let data = ptrace::read(pid, (addr + i) as *mut c_void)?;
		debug!("read {} bytes: 0x{:x}", WORD_SIZE, data);
		for j in 0..WORD_SIZE {
			out.push(((data >> (j * 8)) & 0xFF) as u8);
		}
	}

	Ok(out)
}

pub fn write_buffer(pid: Pid, addr: usize, payload: &[u8]) -> Result<()> {
	let mut at = addr;

	for chunk in payload.chunks(WORD_SIZE) {
		let mut buf : u64 = 0;
		for (i, c) in chunk.iter().enumerate() {
			buf |= (*c as u64) << (i * 8);
		}
		unsafe { ptrace::write(pid, at as *mut c_void, buf as *mut c_void)?; }
		debug!("wrote {} bytes: 0x{:x}", WORD_SIZE, buf);
		at += WORD_SIZE;
	}

	Ok(())
}

pub struct RemoteString {
	pub ptr: Option<usize>,
	pub txt: String,
}

impl RemoteString {
	pub fn new(txt: String) -> Self {
		RemoteString { ptr: None, txt }
	}
}

impl RemoteOperation for RemoteString {
	fn inject(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		let ptr = RemoteMMap::args(
			0, self.txt.len(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0
		).inject(pid, syscall)?;
		write_buffer(pid, ptr as usize, self.txt.as_bytes())?;
		self.ptr = Some(ptr as usize);
		info!("sent '{}'", self.txt);
		Ok(ptr)
	}

	fn revert(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		if let Some(ptr) = self.ptr {
			return RemoteMUnmap::args(ptr, self.txt.len())
				.inject(pid, syscall);
		}
		Ok(0)
	}
}


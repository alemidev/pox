use std::ffi::c_void;

use nix::{Result, unistd::Pid, sys::ptrace, libc::{PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANON}};

use crate::{injector::RemoteOperation, syscalls::RemoteMMap};

const WORD_SIZE : usize = 32;

#[allow(unused)]
pub fn read_buffer(pid: Pid, addr: usize, size: usize) -> Result<Vec<u8>> {
	let mut out = vec![];

	for i in (0..size).step_by(WORD_SIZE/8) {
		let data = ptrace::read(pid, (addr + i) as *mut c_void)?;
		for j in 0..WORD_SIZE/8 {
			out.push(((data >> (j * 8)) & 0xFF) as u8);
		}
	}

	Ok(out)
}

pub fn write_buffer(pid: Pid, addr: usize, payload: &[u8]) -> Result<()> {
	let step = WORD_SIZE / 8;
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
		Ok(ptr)
	}
}


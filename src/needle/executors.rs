use nix::{unistd::Pid, Result, libc::{PROT_READ, MAP_PRIVATE, MAP_ANON, PROT_EXEC}, sys::{ptrace, wait::waitpid}};

use crate::{syscalls::{RemoteMMap, RemoteMUnmap}, senders::{write_buffer, read_buffer, ByteVec}, injector::RemoteOperation};

pub struct RemoteShellcode<'a> {
	code: &'a [u8],
	ptr: Option<u64>,
}

impl<'a> RemoteShellcode<'a> {
	pub fn new(code: &'a [u8]) -> Self {
		RemoteShellcode { code, ptr: None }
	}
}

impl RemoteOperation for RemoteShellcode<'_> {
	fn inject(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		let original_regs = ptrace::getregs(pid)?;
		let ptr = RemoteMMap::args(
			0, self.code.len() + 1, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0
		).inject(pid, syscall)?;
		println!("Obtained area @ 0x{:X}", ptr);
		self.ptr = Some(ptr);
		let mut shellcode = self.code.to_vec();
		shellcode.push(0xCC); // is this the debugger trap?
		write_buffer(pid, ptr as usize, shellcode.as_slice())?;
		let shellcode = read_buffer(pid, ptr as usize, self.code.len() + 1)?;
		println!("Copied shellcode {}", ByteVec::from(shellcode));
		let mut regs = original_regs.clone();
		regs.rip = ptr;
		ptrace::setregs(pid, regs)?;
		ptrace::cont(pid, None)?;
		waitpid(pid, None)?;
		let after_regs = ptrace::getregs(pid)?;
		println!("Executed shellcode (RIP: 0x{:X})", after_regs.rip);
		Ok(ptr)
	}

	fn revert(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		if let Some(ptr) = self.ptr {
			return RemoteMUnmap::args(ptr as usize, self.code.len() + 1)
				.inject(pid, syscall);
		}
		Ok(0)
	}
}

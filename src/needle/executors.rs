use nix::{unistd::Pid, Result, libc::{PROT_READ, MAP_PRIVATE, MAP_ANON, PROT_WRITE}, sys::{ptrace, wait::waitpid}};

use crate::{syscalls::RemoteMMap, senders::write_buffer, injector::RemoteOperation};

pub struct RemoteShellcode<'a> {
	code: &'a [u8],
}

impl<'a> RemoteShellcode<'a> {
	pub fn new(code: &'a [u8]) -> Self {
		RemoteShellcode { code }
	}
}

impl RemoteOperation for RemoteShellcode<'_> {
	fn inject(&mut self, pid: Pid, syscall: usize) -> Result<u64> {
		let original_regs = ptrace::getregs(pid)?;
		let ptr = RemoteMMap::args(
			0, self.code.len(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0
		).inject(pid, syscall)?;
		let mut shellcode = self.code.to_vec();
		shellcode.push(0xCC); // is this the debugger trap?
		write_buffer(pid, ptr as usize, shellcode.as_slice())?;
		let mut regs = original_regs.clone();
		regs.rip = ptr;
		ptrace::setregs(pid, regs)?;
		ptrace::cont(pid, None)?;
		waitpid(pid, None)?;
		ptrace::setregs(pid, original_regs)?;
		Ok(ptr)
	}
}

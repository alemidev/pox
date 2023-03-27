mod syscalls;
mod executors;
mod senders;
mod injector;
mod explorers;

use injector::{RemoteOperation, step_to_syscall};
use nix::{Result, {sys::{ptrace, wait::waitpid}, unistd::Pid}};
use clap::Parser;

use executors::RemoteShellcode;
use senders::RemoteString;
use syscalls::RemoteWrite;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,
}

const SHELLCODE : [u8; 2] = [0x90, 0x90];

pub fn nasty_stuff(pid: Pid) -> Result<()> {
	let syscall_addr = step_to_syscall(pid)?;
	let mut msg = RemoteString::new("injected!\n\0".into());
	msg.inject(pid, syscall_addr)?;
	RemoteWrite::args(1, msg).inject(pid, syscall_addr)?;
	RemoteShellcode::new(&SHELLCODE).inject(pid, syscall_addr)?;
	Ok(())
}

fn main() -> Result<()> {
	let args = NeedleArgs::parse();
	let pid = Pid::from_raw(args.pid);

	ptrace::attach(pid)?;
	waitpid(pid, None)?;

	println!("Attached to process #{}", args.pid);

	let regs = ptrace::getregs(pid)?;
	nasty_stuff(pid)?;
	ptrace::setregs(pid, regs)?;

	ptrace::detach(pid, None)?;

	println!("Released process #{}", args.pid);

	Ok(())
}

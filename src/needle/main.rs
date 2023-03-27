mod syscalls;
mod rce;
mod operations;
mod injector;

use injector::RemoteOperation;
use nix::{Result, {sys::{ptrace, wait::waitpid}, unistd::Pid}};
use clap::Parser;
use operations::step_to_syscall;
use rce::{RemoteString, RemoteShellcode};
use syscalls::RemoteWrite;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,

	/// word size on OS (check with $ getconf WORD_BIT)
	#[arg(long, default_value_t = 32)]
	word: u32,
}

pub fn nasty_stuff(pid: Pid, _word_size: usize) -> Result<()> {
	let original_registers = ptrace::getregs(pid)?;
	let syscall_addr = step_to_syscall(pid)?;
	let mut msg = RemoteString::new("injected!\n\0".into());
	msg.inject(pid, syscall_addr)?;
	RemoteWrite::args(1, msg).inject(pid, syscall_addr)?;
	RemoteShellcode::new(&[0u8]).inject(pid, syscall_addr)?;
	ptrace::setregs(pid, original_registers)?;
	Ok(())
}

fn main() {
	let args = NeedleArgs::parse();
	let pid = Pid::from_raw(args.pid);

	if let Err(e) = ptrace::attach(pid) {
		eprintln!("Could not attach to process : {}", e);
		return;
	}

	if let Err(e) = waitpid(pid, None) {
		eprintln!("Failed waiting for process to stop : {}", e);
	}

	println!("Attached to process #{}", args.pid);

	if let Err(e) = nasty_stuff(pid, args.word as usize) {
		eprintln!("Could not pwn : {}", e);
	}

	if let Err(e) = ptrace::detach(pid, None) {
		eprintln!("Could not resume process : {}", e);
	} else {
		println!("Released process #{}", args.pid);
	}
}

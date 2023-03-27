mod syscalls;
mod operations;

use nix::{Result, {sys::{ptrace, wait::waitpid}, unistd::Pid}};
use clap::Parser;
use operations::step_to_syscall;
use syscalls::{RemoteString, RemoteWrite, RemoteSyscall};

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
	let msg = RemoteString::new(pid, syscall_addr, "injected!\n\0".into())?;
	RemoteWrite::args(1, msg).syscall(pid, syscall_addr)?;
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

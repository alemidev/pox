mod syscalls;

use std::ffi::c_void;
use nix::{Result, {sys::{ptrace, wait::waitpid}, unistd::Pid}};
use clap::Parser;
use syscalls::prepare_exit;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,

	/// word size on OS (check with $ getconf WORD_BIT)
	#[arg(long, default_value_t = 32)]
	word: u32,
}

pub fn write_buffer(pid: Pid, addr: usize, payload: &[u8], word:u32) -> Result<()> {
	let mut buffer = payload.to_vec();

	while buffer.len() % word as usize != 0 {
		buffer.push(0); // pad with zeros because we copy chunks of size 'word'
	}

	for i in (0..buffer.len()).step_by(word as usize) {
		unsafe {
			let offset = (addr + i) as *mut c_void;
			let data = (buffer.as_ptr().add(i)) as *mut c_void;
			ptrace::write(pid, offset, data)?;
		}
	}

	Ok(())
}

pub fn pwn(pid: Pid, _word_size: usize) -> Result<()> {

	let mut prev_regs;
	let mut insn_addr;
	let mut curr_instr;

	loop {
		prev_regs = ptrace::getregs(pid)?;
		insn_addr = prev_regs.rip;
		curr_instr = ptrace::read(pid, insn_addr as *mut c_void)?;
		// println!("@ 0x{:X} [{:x}]", insn_addr, curr_instr);

		if curr_instr & 0xFFFF == 0x050F {
			// println!("found syscall!");
			break;
		}

		ptrace::step(pid, None)?;
		waitpid(pid, None)?;
	}

	// // Put syscall opcodes
	// let mut syscall_insn = vec![0x00u8; word_size/8];
	// syscall_insn[0] = 0x05; // it's two!
	// syscall_insn[1] = 0x0F;

	// unsafe {
	// 	ptrace::write(pid, insn_addr, syscall_insn.as_slice().as_ptr() as *mut c_void)?;
	// }

	let mut call_regs = prev_regs.clone();

	// call_regs.rip = insn_addr;
	prepare_exit(&mut call_regs, 69);
	ptrace::setregs(pid, call_regs)?;
	ptrace::step(pid, None)?;
	waitpid(pid, None)?;

	// restore code and registers
	// unsafe {
	// 	ptrace::write(pid, insn_addr, prev_instr.as_ptr() as *mut c_void)?;
	// }
	// ptrace::setregs(pid, prev_regs)?;

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

	if let Err(e) = pwn(pid, args.word as usize) {
		eprintln!("Could not pwn : {}", e);
	}

	if let Err(e) = ptrace::detach(pid, None) {
		eprintln!("Could not resume process : {}", e);
	} else {
		println!("Released process #{}", args.pid);
	}
}

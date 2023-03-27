mod syscalls;

use std::ffi::c_void;
use nix::{Result, {sys::{ptrace, wait::waitpid}, unistd::Pid}, libc::{PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANON}};
use clap::Parser;
use syscalls::{prepare_mmap, prepare_write};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,

	/// word size on OS (check with $ getconf WORD_BIT)
	#[arg(long, default_value_t = 32)]
	word: u32,
}

pub fn send_str(pid: Pid, syscall_addr: u64, data: &str) -> Result<usize> {
	let mut regs = ptrace::getregs(pid)?;
	regs.rip = syscall_addr;
	prepare_mmap(&mut regs, 0, data.len(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0xFFFFFFFFFFFFFFFF, 0);
	ptrace::setregs(pid, regs)?;
	ptrace::step(pid, None)?;
	waitpid(pid, None)?;
	let zone_addr = ptrace::getregs(pid)?.rax as usize;
	write_buffer(pid, zone_addr, data.as_bytes(), 32)?; // TODO word size!
	Ok(zone_addr)
}

pub fn read_buffer(pid: Pid, addr: usize, size: usize, word: u32) -> Result<Vec<u8>> {
	let mut out = vec![];

	for i in (0..size).step_by((word/8) as usize) {
		let data = ptrace::read(pid, (addr + i) as *mut c_void)?;
		for j in 0..(word/8) as usize {
			out.push(((data >> (j * 8)) & 0xFF) as u8);
		}
	}

	Ok(out)
}

pub fn write_buffer(pid: Pid, addr: usize, payload: &[u8], word:u32) -> Result<()> {
	let step = word / 8;
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

pub fn pwn(pid: Pid, _word_size: usize) -> Result<()> {

	let mut prev_regs;
	let mut insn_addr;
	let mut curr_instr;

	// seek to syscall
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

	let msg = send_str(pid, insn_addr, "injected!\n\0")?;

	let mut call_regs = prev_regs.clone();

	call_regs.rip = insn_addr;

	prepare_write(&mut call_regs, 1, msg, 10);
	ptrace::setregs(pid, call_regs)?;
	ptrace::step(pid, None)?;
	waitpid(pid, None)?;
	// println!("Written payload to stdout on tracee");

	// restore code and registers
	// unsafe {
	// 	ptrace::write(pid, insn_addr, prev_instr.as_ptr() as *mut c_void)?;
	// }

	ptrace::setregs(pid, prev_regs)?;

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

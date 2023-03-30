use std::path::PathBuf;

use tracing::{metadata::LevelFilter, info, error};

use nix::{sys::{ptrace, wait::waitpid}, unistd::Pid};
use clap::Parser;

use rustyneedle::{rc::{
	injector::RemoteOperation, executors::RemoteShellcode,
	senders::RemoteString, syscalls::RemoteExit,
	explorers::step_to_syscall,
}, locators::{procmaps::map_addr_path, exec::offset_in_elf}};

mod monitor;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct NeedleArgs {
	/// target process pid
	pid: i32,

	/// shared object to inject into target process
	#[arg(short, long)]
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

	/// instead of injecting a library, execute an exit syscall with code 69
	#[arg(long, default_value_t = false)]
	kill: bool,

	/// after injecting, keep alive listening for logs
	#[arg(long, default_value_t = false)]
	monitor: bool,
}

fn nasty_stuff(args: NeedleArgs) -> Result<(), Box<dyn std::error::Error>> {
	let pid = Pid::from_raw(args.pid);

	ptrace::attach(pid)?;
	waitpid(pid, None)?;
	info!("attached to process #{}", args.pid);

	// continue running process step-by-step until we find a syscall
	let syscall = step_to_syscall(pid)?; // TODO no real need to step...
	let original_regs = ptrace::getregs(pid)?; // store original regs to restore after injecting

	if args.kill {
		RemoteExit::args(69).exit(pid, syscall)?;
		info!("killed process #{}", args.pid);
		return Ok(());
	}

	// move path to our payload into target address space
	let tetanus = RemoteString::new(args.payload.clone() + "\0")
		.inject(pid, syscall)?;
	
	// find dlopen address
	// TODO make this part less spaghetti
	let dlopen_addr;
	if let Some(addr) = args.addr {
		dlopen_addr = addr;
	} else {
		let (mut calc_base, mut calc_fpath) = (0, "".into()); // rust complains about uninitialized...
		if args.path.is_none() || args.base.is_none() { // if user gives both no need to calculate it
			if let Some((b, p)) = map_addr_path(pid.as_raw(), "libc.so.6")? {
				(calc_base, calc_fpath) = (b, p);
			}
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
			Some(o) => o, // TODO catch error if dlopen is not in symbols
			None    => offset_in_elf(&fpath, "dlopen")?.expect("no dlopen symbol available"),
		};

		dlopen_addr = base + offset;
	}


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
	info!("invoked dlopen('{}', 1) @ 0x{:X}", args.payload, dlopen_addr);

	// restore original registers and detach
	// TODO clean allocated areas
	ptrace::setregs(pid, original_regs)?;
	ptrace::detach(pid, None)?;
	info!("released process #{}", args.pid);

	Ok(())
}

fn main() {
	tracing_subscriber::fmt()
		.with_max_level(LevelFilter::INFO)
		.init();

	let args = NeedleArgs::parse();

	let monitor = args.monitor;

	if let Err(e) = nasty_stuff(args) {
		error!("error injecting shared object: {}", e);
		return;
	}

	if monitor {
		monitor::listen_logs();
	}

}

use nix::libc::user_regs_struct;

fn prepare_for_syscall(regs: &mut user_regs_struct, rax: u64, rdi: u64, rsi: u64, rdx: u64, r10: u64, r8: u64, r9: u64) {
	regs.rax = rax;
	regs.rdi = rdi;
	regs.rsi = rsi;
	regs.rdx = rdx;
	regs.r10 = r10;
	regs.r8  = r8;
	regs.r9  = r9;
}

#[allow(unused)]
pub fn prepare_mmap(regs: &mut user_regs_struct, addr: u64, len: usize, prot: i32, flags: i32, fd: u64, off: u64) {
	prepare_for_syscall(regs, 9, addr, len as u64, prot as u64, flags as u64, fd, off);
}

#[allow(unused)]
pub fn prepare_open(regs: &mut user_regs_struct, filename: &str, flags: u64, mode: u64) {
	prepare_for_syscall(regs, 2, filename.as_ptr() as u64, flags, mode, 0, 0, 0);
}

#[allow(unused)]
pub fn prepare_write(regs: &mut user_regs_struct, fd: u64, buf: usize, count: usize) {
	prepare_for_syscall(regs, 1, fd, buf as u64, count as u64, 0, 0, 0);
}

#[allow(unused)]
pub fn prepare_exit(regs: &mut user_regs_struct, error_code: i64) {
	prepare_for_syscall(regs, 60, error_code as u64, 0, 0, 0, 0, 0);
}

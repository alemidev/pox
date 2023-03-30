use nix::{Result, unistd::Pid};

pub trait RemoteOperation {
	fn inject(&mut self, pid: Pid, syscall: usize) -> Result<u64>;
	fn revert(&mut self, pid: Pid, syscall: usize) -> Result<u64>;
}

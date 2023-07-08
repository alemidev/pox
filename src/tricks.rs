pub struct ByteVec(pub Vec<u8>);

impl From<Vec<u8>> for ByteVec {
	fn from(value: Vec<u8>) -> Self {
		ByteVec(value)
	}
}

impl std::fmt::Display for ByteVec {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "[ ")?;
		for el in self.0.iter() {
			write!(f, "0x{:x} ", el)?;
		}
		write!(f, "]")?;
		Ok(())
	}
}

pub fn find_exec_name() -> Option<std::path::PathBuf> {
	current_exe_name().or_else(|| find_argv0())
}

pub fn current_exe_name() -> Option<std::path::PathBuf> {
	let path = std::env::current_exe().ok()?;
	let filename = path.file_name()?;
	Some(std::path::PathBuf::from(filename))
}

pub fn find_argv0() -> Option<std::path::PathBuf> {
	let argv0 = std::env::args_os().next()?;
	let path = std::path::PathBuf::from(argv0);
	// could be a relative path, just get last member
	let filename = path.file_name()?;
	Some(std::path::PathBuf::from(filename))
}

pub fn fmt_path(p: Option<&std::path::Path>) -> String {
	match p {
		Some(path) => {
			match path.to_str() {
				Some(s) => s.into(),
				None => "?".into(),
			}
		},
		None => "".into(),
	}
}

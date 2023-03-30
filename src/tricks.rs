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

pub fn find_argv0() -> Option<String> { // could be a relative path, just get last member
	Some(std::env::args().next()?.split("/").last()?.into()) // TODO separator for windows?
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

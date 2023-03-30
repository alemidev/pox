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

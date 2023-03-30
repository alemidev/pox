use std::net::TcpListener;

use tracing::info;

pub fn monitor_payload() {
	info!("listening for logs from injected payload ...");
	if let Ok(listener) = TcpListener::bind("127.0.0.1:13337") {
		if let Ok((mut stream, addr)) = listener.accept() {
			info!("incoming data ({})", addr);
			while let Ok(n) = std::io::copy(&mut stream, &mut std::io::stdout()) {
				if n <= 0 { break; }
			}
			info!("connection closed ({})", addr);
		}
	}
}

use std::{net::{TcpListener, TcpStream}, sync::{mpsc, Mutex}, io::{self, Write}};

use tracing::{info, error};

pub fn listen_logs() {
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


// TODO split this into its building blocks, rather than providing a
// complete and non-customizable solution
pub fn prepare_log_collector(addr: String) {
	let (tx, rx) = mpsc::channel();
	tracing_subscriber::fmt()
		.with_writer(Mutex::new(LogSink(tx))) // TODO can we get rid of the mutex by cloning tx?
		.init();
	std::thread::spawn(move || log_dispatcher_worker(&addr, rx, std::time::Duration::from_secs(60)));
}

pub fn log_dispatcher_worker(addr: &str, rx: mpsc::Receiver<String>, reconnect_timeout: std::time::Duration) {
	loop {
		match TcpStream::connect(addr) {
			Ok(mut stream) => {
				loop {
					match rx.recv() {
						Ok(s) => {
							match stream.write_all(s.as_bytes()) {
								Ok(()) => {},
								Err(e) => {
									error!("error sending log message to collector: {}", e);
									break;
								}
							}
						},
						Err(e) => {
							error!("error consuming tracing channel: {}", e);
							break;
						}
					}
				}
			},
			Err(e) => error!("could not connect to log collector: {}", e),
		}
		// don't abuse resources, sleep 30s and try again
		std::thread::sleep(reconnect_timeout);
	}
}

struct LogSink(mpsc::Sender<String>);

impl io::Write for LogSink {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		match std::str::from_utf8(buf) {
			Ok(txt) => {
				match self.0.send(txt.into()) {
					Ok(()) => Ok(buf.len()),
					Err(e) => Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
				}
			},
			Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
		}
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(()) // nothing to do, channel "flushes" itself
	}
}


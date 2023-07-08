# pox
Pox is an infection framework for processes, with tools to manipulate the remote address space.

Pox is built with the PTRACE syscall, so its limited to Linux/BSD systems.

## Usage
Pox itself is a crate providing features to execute remote syscalls, inject remote strings, monitor remote execution and find memory mappings.
Most features can be individually selected while including this crate in your project: `[locator, monitor, rc]`.

Additionally, with the `bin` feature, a sample infection binary will be produced: `vector`.

### Vector
Vector can infect running processes, invoking `dlopen()` remotely and loading a shared object.
It will only work on binaries with glibc linked (no musl support yet).
It can both attack a running process (probably will require root privileges) or spawn a child process and infect it.

Vector will:
 * find a syscall instruction and use it to execute remote actions
 * invoke a remote mmap to allocate a string
 * write shared object path in allocated string
 * calculate dlopen address from system glibc and procmaps
 * force set registers and execute dlopen with previously injected path
 * resume process

## Status
Pox is still under development. I'm building this to explore Linux OS, processes and memory.

# Author notes
This could potentially be used to produce malware, since it helps introduce extraneous libraries into running processes.
However, I believe it's still fine to opensource this:
 * The injection method is pretty old, described on [Phrack](http://phrack.org/issues/59/8.html) in 2002.
 * This only works on Linux/BSD
 * On most most modern systems, PTRACE can't attach other processes if not run from root
 * There are other available projects doing the same thing


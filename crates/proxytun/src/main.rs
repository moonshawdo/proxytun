//! proxytun: run one program, and every process it starts, inside a private
//! network namespace whose only route is a TUN device served by proxytun;
//! its TCP goes to a SOCKS5/HTTP proxy with domain names preserved.

fn main() {
    // The capture side (namespace, TUN, address rewriting) lands in M1.
    eprintln!("proxytun {}: not implemented yet", env!("CARGO_PKG_VERSION"));
    std::process::exit(2);
}

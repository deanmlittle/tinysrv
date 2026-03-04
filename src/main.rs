#![no_std]
#![no_main]

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::abort() }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

const HELP: &[u8] = b"tinysrv - a tiny static http server

usage: tinysrv [root] [port]

args:
  root  (default: .)
  port  (default: 8080)
";

#[no_mangle]
pub extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    unsafe {
        if argc >= 2 {
            let p = *argv.add(1);
            let s = core::slice::from_raw_parts(p, libc::strlen(p.cast()));
            if s == b"-h" || s == b"--help" {
                libc::write(1, HELP.as_ptr().cast(), HELP.len());
                return 0;
            }
        }

        let root = if argc >= 2 {
            let p = *argv.add(1);
            core::slice::from_raw_parts(p, libc::strlen(p.cast()))
        } else {
            b"."
        };

        let port = if argc >= 3 {
            let p = *argv.add(2);
            let s = core::slice::from_raw_parts(p, libc::strlen(p.cast()));
            match u16::from_str_radix(core::str::from_utf8_unchecked(s), 10).ok() {
                Some(p) => p,
                None => {
                    let msg = b"Invalid port\n";
                    libc::write(2, msg.as_ptr().cast(), msg.len());
                    return 1;
                }
            }
        } else {
            8080
        };

        tinysrv::serve(root, port)
    }
}

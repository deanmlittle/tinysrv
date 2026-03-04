#![no_std]

use core::ptr;

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

unsafe fn write_all(fd: i32, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = libc::write(fd, buf.as_ptr().cast(), buf.len());
        if n <= 0 {
            return false;
        }
        buf = &buf[n as usize..];
    }
    true
}

fn fmt_usize(n: usize, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut v = n;
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[i..]
}

unsafe fn stderr(msg: &[u8]) {
    libc::write(2, msg.as_ptr().cast(), msg.len());
}

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------

unsafe fn tcp_listen(port: u16) -> i32 {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
        return -1;
    }

    let yes: libc::c_int = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &yes as *const _ as *const libc::c_void,
        core::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
        #[cfg(target_os = "macos")]
        sin_len: core::mem::size_of::<libc::sockaddr_in>() as u8,
    };

    if libc::bind(
        fd,
        &addr as *const _ as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    ) < 0
    {
        libc::close(fd);
        return -1;
    }

    if libc::listen(fd, 128) < 0 {
        libc::close(fd);
        return -1;
    }

    fd
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Extract the request path from "GET /path HTTP/1.1\r\n..."
/// Returns the slice between the first space and the second space.
fn extract_path<'a>(req: &'a [u8]) -> Option<&'a [u8]> {
    // Must start with "GET "
    if req.len() < 5 || &req[..4] != b"GET " {
        return None;
    }
    let rest = &req[4..];
    // Find the next space (end of path)
    let mut end = 0;
    while end < rest.len() && rest[end] != b' ' {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

/// Hex char to nibble value.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// URL-decode `src` into `dst`. Returns the number of bytes written,
/// or None if the path is invalid (null byte, doesn't start with /).
fn url_decode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    if src.is_empty() || src[0] != b'/' {
        return None;
    }
    let mut si = 0;
    let mut di = 0;
    while si < src.len() && di < dst.len() {
        // Stop at '?' or '#' (query string / fragment)
        if src[si] == b'?' || src[si] == b'#' {
            break;
        }
        if src[si] == b'%' && si + 2 < src.len() {
            if let (Some(hi), Some(lo)) = (hex_val(src[si + 1]), hex_val(src[si + 2])) {
                let ch = (hi << 4) | lo;
                if ch == 0 {
                    return None; // null byte
                }
                dst[di] = ch;
                di += 1;
                si += 3;
                continue;
            }
        }
        dst[di] = src[si];
        di += 1;
        si += 1;
    }
    Some(di)
}

/// Check that a decoded path has no ".." traversal components.
fn has_traversal(path: &[u8]) -> bool {
    // Check for "/.." at any position
    let mut i = 0;
    while i + 2 < path.len() {
        if path[i] == b'/' && path[i + 1] == b'.' && path[i + 2] == b'.' {
            // "/.." at end, or "/../"
            if i + 3 == path.len() || path[i + 3] == b'/' {
                return true;
            }
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// MIME types
// ---------------------------------------------------------------------------

// Category tags: 0=text, 1=image, 2=application, 3=font, 4=video
const MIME_PREFIX: &[&[u8]] = &[
    b"text/", b"image/", b"application/", b"font/", b"video/",
];
const MIME_TABLE: &[(&[u8], u8, &[u8])] = &[
    (b".html",  0, b"html"),
    (b".htm",   0, b"html"),
    (b".css",   0, b"css"),
    (b".js",    0, b"javascript"),
    (b".mjs",   0, b"javascript"),
    (b".json",  2, b"json"),
    (b".txt",   0, b"plain"),
    (b".xml",   0, b"xml"),
    (b".png",   1, b"png"),
    (b".jpg",   1, b"jpeg"),
    (b".jpeg",  1, b"jpeg"),
    (b".gif",   1, b"gif"),
    (b".svg",   1, b"svg+xml"),
    (b".ico",   1, b"x-icon"),
    (b".webp",  1, b"webp"),
    (b".woff",  3, b"woff"),
    (b".woff2", 3, b"woff2"),
    (b".wasm",  2, b"wasm"),
    (b".pdf",   2, b"pdf"),
    (b".mp4",   4, b"mp4"),
    (b".webm",  4, b"webm"),
];

/// Returns (category, subtype). Category 0 (text) gets "; charset=utf-8".
fn mime_for_ext(path: &[u8]) -> (u8, &'static [u8]) {
    let mut dot = path.len();
    let mut i = path.len();
    while i > 0 {
        i -= 1;
        if path[i] == b'.' {
            dot = i;
            break;
        }
        if path[i] == b'/' {
            break;
        }
    }
    if dot < path.len() {
        let ext = &path[dot..];
        let mut j = 0;
        while j < MIME_TABLE.len() {
            let (pat, cat, sub) = MIME_TABLE[j];
            if ext.len() == pat.len() {
                let mut k = 0;
                let mut eq = true;
                while k < ext.len() {
                    let a = if ext[k] >= b'A' && ext[k] <= b'Z' { ext[k] + 32 } else { ext[k] };
                    if a != pat[k] {
                        eq = false;
                        break;
                    }
                    k += 1;
                }
                if eq {
                    return (cat, sub);
                }
            }
            j += 1;
        }
    }
    (2, b"octet-stream")
}

// ---------------------------------------------------------------------------
// File serving
// ---------------------------------------------------------------------------

const RESPONSE_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";

unsafe fn send_404(sock: i32) {
    write_all(sock, RESPONSE_404);
}

const DIR_HDR_A: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ";
const DIR_HDR_B: &[u8] = b"\r\nConnection: close\r\n\r\n";
// Max header: HDR_A(69) + content-length digits(4) + HDR_B(23) = 96
const DIR_HDR_MAX: usize = 128;

unsafe fn send_dir_listing(sock: i32, dirpath: *const libc::c_char) {
    let dir = libc::opendir(dirpath);
    if dir.is_null() {
        send_404(sock);
        return;
    }

    // Reserve header space at the front, build JSON body after it
    let mut buf = [0u8; DIR_HDR_MAX + 8192];
    buf[DIR_HDR_MAX] = b'[';
    let mut pos = DIR_HDR_MAX + 1;
    let mut first = true;

    loop {
        let ent = libc::readdir(dir);
        if ent.is_null() { break; }

        let name_ptr = &(*ent).d_name as *const libc::c_char;
        let name_len = libc::strlen(name_ptr);
        let name = core::slice::from_raw_parts(name_ptr as *const u8, name_len);

        if name == b"." || name == b".." { continue; }

        let extra = if first { 0 } else { 1 };
        let needed = extra + 1 + name_len + 1;
        if pos + needed + 1 >= buf.len() { break; }

        if !first { buf[pos] = b','; pos += 1; }
        buf[pos] = b'"'; pos += 1;
        buf[pos..pos + name_len].copy_from_slice(name);
        pos += name_len;
        buf[pos] = b'"'; pos += 1;
        first = false;
    }

    libc::closedir(dir);

    buf[pos] = b']';
    pos += 1;

    // Format content-length and build headers right before the body
    let body_len = pos - DIR_HDR_MAX;
    let mut len_buf = [0u8; 20];
    let len_str = fmt_usize(body_len, &mut len_buf);

    let hdr_len = DIR_HDR_A.len() + len_str.len() + DIR_HDR_B.len();
    let start = DIR_HDR_MAX - hdr_len;

    let mut h = start;
    buf[h..h + DIR_HDR_A.len()].copy_from_slice(DIR_HDR_A);
    h += DIR_HDR_A.len();
    buf[h..h + len_str.len()].copy_from_slice(len_str);
    h += len_str.len();
    buf[h..h + DIR_HDR_B.len()].copy_from_slice(DIR_HDR_B);

    write_all(sock, &buf[start..pos]);
}

/// Open, stat, and serve a file. If the path is a directory, tries
/// appending /index.html, then falls back to a directory listing.
/// `fullpath` must be a mutable null-terminated buffer with `fp_len`
/// valid bytes before the null.
unsafe fn serve_file(sock: i32, fullpath: &mut [u8; 4096], fp_len: usize) {
    let file_fd = libc::open(fullpath.as_ptr().cast(), libc::O_RDONLY);
    if file_fd < 0 {
        send_404(sock);
        return;
    }

    let mut st: libc::stat = core::mem::zeroed();
    if libc::fstat(file_fd, &mut st) < 0 {
        libc::close(file_fd);
        send_404(sock);
        return;
    }

    // If directory, try /index.html first, then fall back to listing
    if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        libc::close(file_fd);
        let idx = b"/index.html";
        if fp_len + idx.len() < fullpath.len() {
            fullpath[fp_len..fp_len + idx.len()].copy_from_slice(idx);
            fullpath[fp_len + idx.len()] = 0;
            let fd2 = libc::open(fullpath.as_ptr().cast(), libc::O_RDONLY);
            if fd2 >= 0 && libc::fstat(fd2, &mut st) == 0 {
                return send_response(sock, fd2, &fullpath[..fp_len + idx.len()], &st);
            }
            if fd2 >= 0 { libc::close(fd2); }
        }
        // Restore original null terminator and list the directory
        fullpath[fp_len] = 0;
        return send_dir_listing(sock, fullpath.as_ptr().cast());
    }

    send_response(sock, file_fd, &fullpath[..fp_len], &st);
}

unsafe fn send_response(sock: i32, file_fd: i32, filepath: &[u8], st: &libc::stat) {
    let file_size = st.st_size as usize;
    let (cat, sub) = mime_for_ext(filepath);

    let mut len_buf = [0u8; 20];
    let len_str = fmt_usize(file_size, &mut len_buf);

    write_all(sock, b"HTTP/1.1 200 OK\r\nContent-Type: ");
    write_all(sock, MIME_PREFIX[cat as usize]);
    write_all(sock, sub);
    if cat == 0 { write_all(sock, b"; charset=utf-8"); }
    write_all(sock, b"\r\nContent-Length: ");
    write_all(sock, len_str);
    write_all(sock, b"\r\nConnection: close\r\n\r\n");

    let mut buf = [0u8; 8192];
    loop {
        let n = libc::read(file_fd, buf.as_mut_ptr().cast(), buf.len());
        if n <= 0 { break; }
        if !write_all(sock, &buf[..n as usize]) { break; }
    }

    libc::close(file_fd);
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

unsafe fn handle(sock: i32, root: &[u8]) {
    let mut req_buf = [0u8; 4096];
    let n = libc::read(sock, req_buf.as_mut_ptr().cast(), req_buf.len());
    if n <= 0 {
        return;
    }

    let req = &req_buf[..n as usize];

    // Extract request path
    let raw_path = match extract_path(req) {
        Some(p) => p,
        None => {
            send_404(sock);
            return;
        }
    };

    // URL-decode into stack buffer
    let mut decoded = [0u8; 2048];
    let path_len = match url_decode(raw_path, &mut decoded) {
        Some(len) => len,
        None => {
            send_404(sock);
            return;
        }
    };
    let path = &decoded[..path_len];

    // Path traversal check
    if has_traversal(path) {
        send_404(sock);
        return;
    }

    // Build full filesystem path: root + path + maybe "index.html" + null
    let mut fullpath = [0u8; 4096];
    let mut fp_len = 0;

    // Copy root (strip trailing slash if present)
    let root_trimmed = if root.last() == Some(&b'/') { &root[..root.len() - 1] } else { root };
    if fp_len + root_trimmed.len() >= fullpath.len() {
        send_404(sock);
        return;
    }
    fullpath[fp_len..fp_len + root_trimmed.len()].copy_from_slice(root_trimmed);
    fp_len += root_trimmed.len();

    // Copy decoded path
    if fp_len + path_len >= fullpath.len() {
        send_404(sock);
        return;
    }
    fullpath[fp_len..fp_len + path_len].copy_from_slice(path);
    fp_len += path_len;

    // Null-terminate
    fullpath[fp_len] = 0;

    // serve_file handles directory detection, index.html fallback, and listing
    serve_file(sock, &mut fullpath, fp_len);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a static file server on `port`, serving files from `root`.
/// Blocks forever. Returns -1 if binding fails.
///
/// # Safety
/// Calls libc functions directly.
pub unsafe fn serve(root: &[u8], port: u16) -> i32 {
    let listener = tcp_listen(port);
    if listener < 0 {
        return -1;
    }

    stderr(b"Listening on http://127.0.0.1:");
    let mut port_buf = [0u8; 20];
    let port_str = fmt_usize(port as usize, &mut port_buf);
    stderr(port_str);
    stderr(b"\n");

    loop {
        let client = libc::accept(listener, ptr::null_mut(), ptr::null_mut());
        if client < 0 {
            continue;
        }
        handle(client, root);
        libc::close(client);
    }
}

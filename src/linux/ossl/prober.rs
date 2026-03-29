// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{io, io::Read, os::fd::AsRawFd, slice};

use libc::size_t;

const MAX_HAYSTACK: size_t = 4 * 1024;
const USIZE_SIZE: usize = std::mem::size_of::<usize>();

#[derive(Copy, Clone)]
pub enum MemmemMode {
    AssumeLibc,
    Fork,
    AssumeLibcAndFork,
}

pub(crate) struct Tls13SecretOffsetProber {
    mode: MemmemMode,
    client_secret: Option<Vec<u8>>,
    server_secret: Option<Vec<u8>>,
}

impl Tls13SecretOffsetProber {
    // SAFETY: the caller must comply to the protocol of the given MemmemMode to
    // avoid undefined behavior.
    pub(crate) unsafe fn new(mode: MemmemMode) -> Self {
        Self {
            mode,
            client_secret: None,
            server_secret: None,
        }
    }

    pub(crate) fn feed_keylog(&mut self, line: &[u8]) {
        let extract_secret_from_keylog = |prefix| {
            line.starts_with(prefix)
                .then(|| line.rsplit(|&b| b == b' '))?
                .next()?
                .chunks(2)
                .map(|chunk| match chunk {
                    &[h, l] => Some(
                        ((h as char).to_digit(16)? as u8) << 4 | (l as char).to_digit(16)? as u8,
                    ),
                    _ => None,
                })
                .collect()
        };
        self.client_secret = self
            .client_secret
            .take()
            .or_else(|| extract_secret_from_keylog(b"CLIENT_TRAFFIC_SECRET_0"));
        self.server_secret = self
            .server_secret
            .take()
            .or_else(|| extract_secret_from_keylog(b"SERVER_TRAFFIC_SECRET_0"));
    }

    pub(crate) fn probe(&self, ssl: *const u8) -> io::Result<(usize, usize)> {
        match &self {
            Self {
                mode,
                client_secret: Some(client_secret),
                server_secret: Some(server_secret),
            } => {
                // SAFETY: the caller has complied to the MemmemMode protocol
                let client_offset = unsafe { memmem(ssl, client_secret, *mode) }?;
                let server_offset = unsafe { memmem(ssl, server_secret, *mode) }?;
                Ok((client_offset, server_offset))
            }
            _ => Err(io::Error::other("don't have all secrets yet")),
        }
    }

    pub(crate) fn verify(
        &self,
        ssl: *const u8,
        client_secret_offset: usize,
        server_secret_offset: usize,
    ) -> io::Result<bool> {
        match &self {
            Self {
                client_secret: Some(client_secret),
                server_secret: Some(server_secret),
                ..
            } => {
                // SAFETY: the SSL struct layout is stable in the same process, so the secret
                // offsets found previously should be valid up to the secret lengths
                let extracted_client_secret = unsafe {
                    slice::from_raw_parts(ssl.add(client_secret_offset), client_secret.len())
                };
                let extracted_server_secret = unsafe {
                    slice::from_raw_parts(ssl.add(server_secret_offset), server_secret.len())
                };
                Ok(client_secret == extracted_client_secret
                    && server_secret == extracted_server_secret)
            }
            _ => Err(io::Error::other("don't have all secrets yet")),
        }
    }
}

// SAFETY: the caller must comply to the protocol of the given MemmemMode to
// avoid undefined behavior
unsafe fn memmem(haystack: *const u8, needle: &[u8], mode: MemmemMode) -> io::Result<usize> {
    // Short needle
    let needle_len = needle.len();
    if needle_len == 0 {
        return Ok(0);
    }

    // Pile up the haystack
    use MemmemMode::*;
    let haystack_len = match mode {
        AssumeLibc | AssumeLibcAndFork => {
            // SAFETY: caller assumes that the haystack was allocated by libc
            let size = unsafe { libc::malloc_usable_size(haystack as _) };
            if size >= 1 {
                Ok(size.min(MAX_HAYSTACK))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "haystack is not libc-allocated or too small",
                ))
            }
        }
        Fork => Ok(MAX_HAYSTACK),
    }?;
    if needle_len > haystack_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "needle is longer than haystack",
        ));
    }

    // Now find the needle in the haystack
    match mode {
        // SAFETY: we are requested to fork
        Fork | AssumeLibcAndFork => unsafe { memmem_fork(haystack, haystack_len, needle) },

        // SAFETY: haystack_len is assumed to be always valid
        AssumeLibc => unsafe { slice::from_raw_parts(haystack, haystack_len) }
            .windows(needle_len)
            .position(|window| window == needle)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "needle not found in haystack")),
    }
}

// SAFETY: this function forks the process without exec. Even though we are very
// careful in the subprocess, but the caller should still be aware of the fork.
unsafe fn memmem_fork(
    haystack: *const u8,
    haystack_len: size_t,
    needle: &[u8],
) -> io::Result<usize> {
    // Prepare a pipe
    let (mut r, w) = io::pipe()?;
    let r_fd = r.as_raw_fd();
    let w_fd = w.as_raw_fd();

    // Fork a crash-safe subprocess
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // Child, be extremely careful!
        // SAFETY: this contains only async-signal-safe operations, and always _exit()
        unsafe {
            if libc::close(r_fd) != 0 {
                libc::_exit(libc::EXIT_FAILURE);
            }
            memmem_child(haystack, haystack_len, needle, w_fd);
        }
    } else {
        // Parent, read back the result (but don't return just yet)
        drop(w);
        let mut buf = [0; USIZE_SIZE];
        let res = match r.read_exact(&mut buf).map(|()| usize::from_ne_bytes(buf)) {
            Ok(rv) if rv + needle.len() <= haystack_len => Ok(rv),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "needle not found in haystack",
            )),
            Err(e) => Err(io::Error::other(format!(
                "failed to find needle in subprocess: {e}"
            ))),
        };

        // Gracefully wait for the child to exit (always)
        let mut status = 0;
        let waitpid_res = unsafe { libc::waitpid(pid, &mut status, 0) };
        let res = res?;
        if waitpid_res == -1 {
            return Err(io::Error::last_os_error());
        }
        drop(r);

        // Recover from a crashed subprocess. Theoretically, only the happy path is
        // possible, given that we received a valid return value from the pipe; but
        // let's be defensive just in case.
        match libc::WIFEXITED(status) {
            true => match libc::WEXITSTATUS(status) {
                libc::EXIT_SUCCESS => Ok(res),
                libc::EXIT_FAILURE => Err(io::Error::other("subprocess failed to find the needle")),
                _ => unreachable!("new exit code"),
            },
            false => match libc::WIFSIGNALED(status) {
                true => match libc::WTERMSIG(status) {
                    libc::SIGSEGV | libc::SIGBUS => Ok(res),
                    sig => Err(io::Error::other(format!(
                        "subprocess terminated by unexpected signal: {sig}"
                    ))),
                },
                false => Ok(res),
            },
        }
    }
}

// SAFETY: this function is designed to crash, allowing haystack_len to be
// greater than the actual allocated size of the haystack. It must only be
// called in a subprocess that is safe to crash.
unsafe fn memmem_child(
    haystack: *const u8,
    haystack_len: usize,
    needle: &[u8],
    output_fd: libc::c_int,
) -> ! {
    // SAFETY: This function contains only async-signal-safe operations
    unsafe {
        // Disable core dumps to avoid leaving a mess if we crash
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
            libc::_exit(libc::EXIT_FAILURE);
        }

        // Search for the needle in the haystack
        let needle_len = needle.len();
        let mut i = 0usize;
        while i + needle_len <= haystack_len {
            let mut j = 0;
            while j < needle_len && *haystack.add(i + j) == needle[j] {
                j += 1;
            }
            if j == needle_len {
                break;
            }
            i += 1;
        }

        // Write the result back to the parent process
        let written = libc::write(output_fd, &i as *const _ as _, USIZE_SIZE);
        if written == USIZE_SIZE as _ {
            libc::_exit(libc::EXIT_SUCCESS);
        } else {
            libc::_exit(libc::EXIT_FAILURE);
        }
    }
}

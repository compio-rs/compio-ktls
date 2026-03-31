# compio-ktls

Kernel TLS (kTLS) support for [Compio](https://github.com/compio-rs/compio).

[![中文](https://img.shields.io/badge/Zh-中文-informational?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAQCAYAAAAWGF8bAAAAAXNSR0IArs4c6QAAAERlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAFKADAAQAAAABAAAAEAAAAABHXVY9AAABc0lEQVQ4EaWSOy8EURTHd+wDEY94JVtgg9BI1B6dQqHiE1CrRasT30DpC2hVQimiFkJWVsSj2U1EsmQH4/ff3CO3WDuDk/zmf8/jnntm7qRSMRZFUQ4WYSimNFmaRlsgq8F83K6WuALyva4mixbc+kfJcGqa7CqU4AjaocNpG5oHsx7qB3EqQRC8K4g/gazAMbFTBdbgL1Zh0w2EbnMVHdMrd4LZNotZmIZJKMAemC2z0MS6oDlYhzOQ6c3yGR5Fec4OGPvEHCmn3np+kfyT51+QH8afcbFLTfjgFVS9tZrpwC4v1k9M39w3NTQrBxSM4127SAmNoBt0Ma3QyHRwGUIYdQUh0+c0wZsLPKKH8AwvoHgNlmABZLtwBdqnP0DD9IEG2If6N0oz5SbYSfW4PYhvgNmUxU1JZGEEAsUyjPmB7lhBA1Xe7NMWpuzXa39fnC7lN1b/mZttSNLQv9XXZs2US9LwzjU5R+/d+n/CBx9I2uELeXrRajeDqHwAAAAASUVORK5CYII=)](README.zh.md)
[![CI](https://img.shields.io/github/actions/workflow/status/compio-rs/compio-ktls/ci.yml?label=CI&logo=github)](https://github.com/compio-rs/compio-ktls/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-success?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAgCAYAAAASYli2AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAGqSURBVHgBrVbtcYMwDFVy/V82KCMwAp2g2aDtJGSDZoPQDegE0AmSDUwngA1UKYggHBtwyLvTgcF66ONZCcAdQMSMrCEzZHGILzvHZJFaf+AYxxCyTDlmQm5k3cj1EEJ4Qjf085322UI4KrJrCTabTXFDKKmU8uUjWSLvfy2yWixWWbDf16g58tBGadWQsUc/GuZ6Es4YbpGK6ehewI9iLkIMiO7Up7z11AoctcOJyF6pObWOMMJBVy6wmI0rapv9EiGxt3T5nIiOETvePaN99LCTTCL3B0/tfALvYbCTWww4pFJ6HHe4HCXLppVgU0dKP2RvsBwJzESwQ3czfDj0dXRpzODydFkhe+a6nBTqMhPybabCrybSzaUcrVgtSrl2miPhbufqqyn6tWnQN6lxPIGbgHSNi4+FHal1tCDdHt+uh1zDs2ez/VtRy94/soJqVoEPOD4hjdTPrlkKIVANOaJ/VBVzPP2AZelwc2pJ7d2xl2WRw1JC5VQJKc/Ivkm8zkdaWwJ0zLdQbBVZBMOgWE8I3bSpYCU0YUI1OsNK3PPPYZ5QDnoND8A/4kV4DUnNfc8AAAAASUVORK5CYII=)](https://www.apache.org/licenses/LICENSE-2.0)
[![license](https://img.shields.io/badge/license-MulanPSL--2.0-success?logo=opensourceinitiative&logoColor=white)](https://license.coscl.org.cn/MulanPSL2/)

## Overview

- Built on top of [ktls-core](https://github.com/hanyu-dev/ktls)
- Not tied to any specific Compio runtime implementation
- Pluggable TLS implementations (currently supports Rustls and OpenSSL)
- Currently supports TLS 1.3 only
- Supports NewSessionTicket, KeyUpdate, and Alert message handling
- Supports splitting `KtlsStream` into read/write halves for concurrent I/O

## Features

- `rustls` (default): Enable Rustls integration
- `openssl`: Enable OpenSSL integration. This uses the `openssl` crate and requires OpenSSL
  to be installed on the system.
- `ring`: Use ring as the crypto backend
- `app-write-with-empty-ancillary`: Use `write_with_ancillary()` instead of `write()` for
  application data writes. compio-rs/compio#756 introduced zero-copy writes for io-uring,
  which changed the default behavior of `write()` in a way that breaks on kTLS-enabled
  sockets. Enable this feature when using io-uring to work around the conflict between
  zero-copy writes and kTLS.
- `key_update`: Enable kTLS key update support (requires Linux 6.13+). Use this to
  force-enable key update when cross-compiling for a 6.13+ target. On native builds you
  typically don't need to set this manually — use `detect_key_update_at_build` instead.
- `detect_key_update_at_build`: Probe the build-host kernel version at compile time. If the
  running kernel is >= 6.13, key update support is enabled automatically; otherwise it is
  disabled even if the `key_update` feature is on. This is the recommended mode for native
  builds and CI.
- `sync`: Use thread-safe locks for the split read/write halves. By default, single-threaded
  (unsync) locks are used. Enable this feature if you need to use the split halves across
  threads.

## Usage

```rust
use compio_ktls::{KtlsConnector, KtlsAcceptor};

// Client side
let connector = KtlsConnector::from(client_config);
match connector.connect("example.com", tcp_stream).await? {
    Ok(stream) => {
        // kTLS enabled successfully
    }
    Err(stream) => {
        // kTLS unavailable, fallback to original stream
    }
}

// Server side
let acceptor = KtlsAcceptor::from(server_config);
match acceptor.accept(tcp_stream).await? {
    Ok(stream) => {
        // kTLS enabled successfully
    }
    Err(stream) => {
        // kTLS unavailable, fallback to original stream
    }
}
```

You can split a `KtlsStream` into independent read and write halves for concurrent I/O:

```rust
use compio::io::util::Splittable;

let (mut reader, mut writer) = stream.split();
// Now reader and writer can be used concurrently
```

## Requirements

Requires Linux kernel with kTLS support, version 6.6 LTS or newer is recommended.

Check if the kTLS module is loaded:

```bash
lsmod | grep tls
```

If not loaded, you can manually load it:

```bash
sudo modprobe tls
```

Also requires Rustls with `enable_secret_extraction` enabled:

```rust
use std::sync::Arc;
use rustls::ClientConfig;

let mut config = ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(/* ... */)
    .with_no_client_auth();

config.enable_secret_extraction = true;

let config = Arc::new(config);
```

### OpenSSL

When using the `openssl` feature, compio-ktls needs to extract TLS traffic secrets from the
OpenSSL `SSL` struct in order to configure kTLS. Because OpenSSL does not expose a public API
for this, the library searches for the secrets directly in the struct's memory — this is
controlled by the **`MemmemMode`** setting:

| Mode | How it works | Trade-off |
|------|-------------|-----------|
| `Fork` (default) | Forks a child process to safely scan the `SSL` struct memory | Safe; assumes nothing about the allocator |
| `AssumeLibc` | Uses `malloc_usable_size` to determine the readable range, then scans in-process | No fork, but assumes OpenSSL allocates with libc `malloc` |
| `AssumeLibcAndFork` | Uses `malloc_usable_size` for the readable range (like `AssumeLibc`), but scans via fork (like `Fork`) | Tighter read bound than pure `Fork`, still fork-safe |

The probed offsets are cached globally (`OnceLock`), so the cost is only paid once — on the
first connection. Subsequent connections reuse the cached result regardless of mode.

The default is `Fork`, which works out of the box. You can switch to a different mode with
`set_memmem_mode`:

```rust
use compio_ktls::{KtlsConnector, MemmemMode};

let mut connector = KtlsConnector::from(ssl_connector);
connector.set_memmem_mode(MemmemMode::AssumeLibc);
```

## License

Licensed under either of:

- Apache License, Version 2.0
- Mulan Permissive Software License, Version 2

`SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0`

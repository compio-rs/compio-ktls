# compio-ktls

Kernel TLS (kTLS) support for [Compio](https://github.com/compio-rs/compio).

[![中文](https://img.shields.io/badge/Zh-中文-informational?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAQCAYAAAAWGF8bAAAAAXNSR0IArs4c6QAAAERlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAFKADAAQAAAABAAAAEAAAAABHXVY9AAABc0lEQVQ4EaWSOy8EURTHd+wDEY94JVtgg9BI1B6dQqHiE1CrRasT30DpC2hVQimiFkJWVsSj2U1EsmQH4/ff3CO3WDuDk/zmf8/jnntm7qRSMRZFUQ4WYSimNFmaRlsgq8F83K6WuALyva4mixbc+kfJcGqa7CqU4AjaocNpG5oHsx7qB3EqQRC8K4g/gazAMbFTBdbgL1Zh0w2EbnMVHdMrd4LZNotZmIZJKMAemC2z0MS6oDlYhzOQ6c3yGR5Fec4OGPvEHCmn3np+kfyT51+QH8afcbFLTfjgFVS9tZrpwC4v1k9M39w3NTQrBxSM4127SAmNoBt0Ma3QyHRwGUIYdQUh0+c0wZsLPKKH8AwvoHgNlmABZLtwBdqnP0DD9IEG2If6N0oz5SbYSfW4PYhvgNmUxU1JZGEEAsUyjPmB7lhBA1Xe7NMWpuzXa39fnC7lN1b/mZttSNLQv9XXZs2US9LwzjU5R+/d+n/CBx9I2uELeXrRajeDqHwAAAAASUVORK5CYII=)](README.zh.md)
[![CI](https://img.shields.io/github/actions/workflow/status/compio-rs/compio-ktls/ci.yml?label=CI&logo=github)](https://github.com/compio-rs/compio-ktls/actions/workflows/ci.yml)b
[![license](https://img.shields.io/badge/license-Apache--2.0-success?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAgCAYAAAASYli2AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAGqSURBVHgBrVbtcYMwDFVy/V82KCMwAp2g2aDtJGSDZoPQDegE0AmSDUwngA1UKYggHBtwyLvTgcF66ONZCcAdQMSMrCEzZHGILzvHZJFaf+AYxxCyTDlmQm5k3cj1EEJ4Qjf085322UI4KrJrCTabTXFDKKmU8uUjWSLvfy2yWixWWbDf16g58tBGadWQsUc/GuZ6Es4YbpGK6ehewI9iLkIMiO7Up7z11AoctcOJyF6pObWOMMJBVy6wmI0rapv9EiGxt3T5nIiOETvePaN99LCTTCL3B0/tfALvYbCTWww4pFJ6HHe4HCXLppVgU0dKP2RvsBwJzESwQ3czfDj0dXRpzODydFkhe+a6nBTqMhPybabCrybSzaUcrVgtSrl2miPhbufqqyn6tWnQN6lxPIGbgHSNi4+FHal1tCDdHt+uh1zDs2ez/VtRy94/soJqVoEPOD4hjdTPrlkKIVANOaJ/VBVzPP2AZelwc2pJ7d2xl2WRw1JC5VQJKc/Ivkm8zkdaWwJ0zLdQbBVZBMOgWE8I3bSpYCU0YUI1OsNK3PPPYZ5QDnoND8A/4kV4DUnNfc8AAAAASUVORK5CYII=)](https://www.apache.org/licenses/LICENSE-2.0)
[![license](https://img.shields.io/badge/license-MulanPSL--2.0-success?logo=opensourceinitiative&logoColor=white)](https://license.coscl.org.cn/MulanPSL2/)

## Overview

- Built on top of [ktls-core](https://github.com/hanyu-dev/ktls)
- Not tied to any specific Compio runtime implementation
- Pluggable TLS implementations (currently supports Rustls)
- Currently supports TLS 1.3 only
- Supports NewSessionTicket, KeyUpdate, and Alert message handling
- Supports splitting `KtlsStream` into read/write halves for concurrent I/O

## Features

- `rustls` (default): Enable Rustls integration
- `ring`: Use ring as the crypto backend
- `app-write-with-empty-ancillary`: Use `write_with_ancillary()` instead of `write()` for
  application data writes. compio-rs/compio#756 introduced zero-copy writes for io-uring,
  which changed the default behavior of `write()` in a way that breaks on kTLS-enabled
  sockets. Enable this feature when using io-uring to work around the conflict between
  zero-copy writes and kTLS.
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

## License

Licensed under either of:

- Apache License, Version 2.0
- Mulan Permissive Software License, Version 2

`SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0`

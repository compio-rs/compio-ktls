# compio-ktls

[Compio](https://github.com/compio-rs/compio) 的内核 TLS (kTLS) 支持！

[![English](https://img.shields.io/badge/英文-English-informational?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAQCAYAAADnEwSWAAAABGdBTUEAALGPC/xhBQAAADhlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAAqACAAQAAAABAAAAG6ADAAQAAAABAAAAEAAAAACiF0fSAAABJUlEQVQ4EWP8//8/MwMDAysQEw0YGRl/EK0YWSHQsgogJgX8RNZPCpuJFMWUqqWrZSw4XBsCFL+FQ+4/DnEUYWC8gNKCEDB+X8MlgIKVWCJMD64ADwOorwmIHyNhdyDbFYgPAfFXIAaBV0CcCTIG5DNsLo0GKnDEYc8+oGsvQ+UEgLQMkrpYIDsSiJGjRxTInwY07wmuYCxDMgCdmQUUgFmGLheNLoDEzwG5gBFJgFQmNr3ZQEPsgfgImmEquHy2BajwHZpiGPcmjAGk0aPgCDCIp4HkgcHWA6RsQGwoEMEVZ9VATZdgqkig7yKp/YjEBjORIxJdjhw+3tIFVzCGAoPBEo9ta4E+f4NHHqsULstqsKpGCJ4BMkm2jNrBiHAOFhZdLQMA8pKhkQYZiokAAAAASUVORK5CYII=)](README.md)
[![CI](https://img.shields.io/github/actions/workflow/status/compio-rs/compio-ktls/ci.yml?label=CI&logo=github)](https://github.com/compio-rs/compio-ktls/actions/workflows/test.yml)
[![许可](https://img.shields.io/badge/许可-Apache--2.0-success?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAgCAYAAAASYli2AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAGqSURBVHgBrVbtcYMwDFVy/V82KCMwAp2g2aDtJGSDZoPQDegE0AmSDUwngA1UKYggHBtwyLvTgcF66ONZCcAdQMSMrCEzZHGILzvHZJFaf+AYxxCyTDlmQm5k3cj1EEJ4Qjf085322UI4KrJrCTabTXFDKKmU8uUjWSLvfy2yWixWWbDf16g58tBGadWQsUc/GuZ6Es4YbpGK6ehewI9iLkIMiO7Up7z11AoctcOJyF6pObWOMMJBVy6wmI0rapv9EiGxt3T5nIiOETvePaN99LCTTCL3B0/tfALvYbCTWww4pFJ6HHe4HCXLppVgU0dKP2RvsBwJzESwQ3czfDj0dXRpzODydFkhe+a6nBTqMhPybabCrybSzaUcrVgtSrl2miPhbufqqyn6tWnQN6lxPIGbgHSNi4+FHal1tCDdHt+uh1zDs2ez/VtRy94/soJqVoEPOD4hjdTPrlkKIVANOaJ/VBVzPP2AZelwc2pJ7d2xl2WRw1JC5VQJKc/Ivkm8zkdaWwJ0zLdQbBVZBMOgWE8I3bSpYCU0YUI1OsNK3PPPYZ5QDnoND8A/4kV4DUnNfc8AAAAASUVORK5CYII=)](https://www.apache.org/licenses/LICENSE-2.0)
[![许可](https://img.shields.io/badge/许可-MulanPSL--2.0-success?logo=opensourceinitiative&logoColor=white)](https://license.coscl.org.cn/MulanPSL2/)

## 概述

- 基于 [ktls-core](https://github.com/hanyu-dev/ktls) 实现
- 不锁定特定的 Compio 运行时实现
- 可插拔的 TLS 实现（目前支持 Rustls）
- 目前仅支持 TLS 1.3
- 支持 NewSessionTicket、KeyUpdate 和 Alert 消息处理
- 支持读写分离（不是那种读写互斥式的），实现真正意义上的并发 I/O

## 可选 features

- `rustls`（默认）：启用 Rustls 集成
- `ring`：使用 ring 作为加密后端
- `sync`：单线程无须开启，多线程才需要。仅对读写分离有用。

## 使用方法

```rust
use compio_ktls::{KtlsConnector, KtlsAcceptor};

// 客户端
let connector = KtlsConnector::from(client_config);
match connector.connect("example.com", tcp_stream).await? {
    Ok(stream) => {
        // 成功启用 kTLS
    }
    Err(stream) => {
        // kTLS 不可用，回退到原始 stream
    }
}

// 服务端
let acceptor = KtlsAcceptor::from(server_config);
match acceptor.accept(tcp_stream).await? {
    Ok(stream) => {
        // 成功启用 kTLS
    }
    Err(stream) => {
        // kTLS 不可用，回退到原始 stream
    }
}
```

可以将 `KtlsStream` 拆分为“独立”的读、写两半，在不同的协程上并发使用：

```rust
use compio::io::util::Splittable;

let (mut reader, mut writer) = stream.split();
// 现在 reader 和 writer 可以并发使用
```

除了比如 KeyUpdate 这种内部处理的特殊消息之外，读写两半之间没有任何交互了，所以不需要担心死锁问题。

## 环境要求

需要 Linux 内核支持 kTLS，建议使用 6.6 或更新版本的 LTS 内核。

检查内核是否已加载 kTLS 模块：

```bash
lsmod | grep tls
```

如果没有加载，可以手动加载：

```bash
sudo modprobe tls
```

另需 Rustls 启用 `enable_secret_extraction`：

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

## 致谢

- 我大幅参考了 [ktls-core](https://github.com/hanyu-dev/ktls) 的实现，但介于 I/O 不兼容无法 100%
  直接用，所以很多东西只能重写一遍，致谢的同时，许愿之后能合并到上游！
- `adaptor.rs` 是仿照 [compio-tls](https://github.com/compio-rs/compio/tree/main/compio-tls) 来做的。

## 许可证

可选以下任一许可证：

- Apache License, Version 2.0
- 木兰宽松许可证，第 2 版

`SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0`

# smoltcp 本地维护补丁

项目通过 `[patch.crates-io]` 使用 `vendor/smoltcp`。它保留完整上游发布包、
原作者归属和 **0BSD** 许可证；产品只启用内存 IP medium，不启用虚拟网卡或 raw socket。
GlobalProtect 协议是独立 Rust 实现，没有复制 OpenConnect 的 GPL 实现。

## 来源

- 上游：smoltcp **0.14.0**。
- 官方 `.crate` SHA-256：`b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`。
- 包内记录的上游提交：`cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3`。
- 唯一修改文件：`src/socket/tcp.rs`，包含生产修复及单元测试。
- 完整差异：[gp-proxy-snd-max.patch](../vendor/smoltcp/gp-proxy-snd-max.patch)。
- 许可原文：[LICENSE-0BSD.txt](../vendor/smoltcp/LICENSE-0BSD.txt)。

## 修复范围与取舍

1. 分离重传游标、实际已发送边界 SND.MAX 和纯 ACK 序列边界，拒绝确认从未发出
   的字节，避免 RTO 或未确认的新字节零窗口探测破坏双向 ACK 进展。
2. 仅对不带 payload/control 且 ACK 有效的纯 ACK 接受 `SEQ == window_end`。
   这是对严格接收窗口表的局部扩展，不扩大数据窗口，也不放宽 SYN/FIN/RST 校验。
3. 零窗口下 RTO 转入 persist；发送队列清空后退出 persist，保留未确认 FIN 的
   正常发送和重传，避免无探测的停滞或纯 ACK 风暴。

序列比较保留 wrapping 语义，输出失败不推进已发送边界，不禁用拥塞控制。
这是本项目维护的补丁，不能视作通用 TCP 兼容性证明或上游已经包含的行为。

## 验证与升级

```sh
cargo test --locked --test tcp_regressions --test tcp_fin_regression \
  --test tcp_syn_regression --test tcp_window_shrink
cargo test --locked --manifest-path vendor/smoltcp/Cargo.toml \
  --no-default-features \
  --features std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-tcp-cubic,socket-udp \
  --lib
python3 scripts/check-vendor.py --self-check
python3 scripts/check-vendor.py --archive /path/to/smoltcp-0.14.0.crate
```

来源检查校验官方包摘要、全部原始文件及规范 unified diff；不解压执行归档、不联网，
只排除生成的 `target/`。发布包内的 `Cargo.lock` 必须随 vendor 提交，即使上游
`.gitignore` 忽略它。来源核验需要完整原始目录，不能为精简仓库删掉上游文件。

升级时先核对新版本、许可与差异，再运行上游单元测试和本项目 TCP/背压/故障回归。
只有新版本覆盖所需行为并通过回归，才移除或缩减补丁；不要静默丢弃测试。

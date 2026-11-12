# 有界、覆盖率引导的解析器 fuzz

这是独立的开发 workspace，正常 `cargo build/test` 和产品分发均不引入
libFuzzer。产品保持 Rust 1.91.0；本工具实测使用隔离的
`nightly-2026-11-10`、cargo-fuzz 0.13.2 和 libfuzzer-sys 0.4.13。
libFuzzer 的 C++ 运行时只用于开发测试，不是 VPN/网络栈/代理实现。

`gp_boundary` 将首字节作为选择器，调用产品实际的 GP 配置 XML、登录
JNLP、IP/keepalive 帧 parser，以及代理目标名称规范化。成功帧要求编码后
可再解码、目标规范化要求幂等，配置和登录检查授权字段的边界。
`seeds/gp_boundary` 的 12 个输入全部是合成数据；不读取 `.env`、会话、
生产抓包或网络。当前不覆盖私有 DNS parser、HTTP/TLS 字节入口及整个会话。

先按 [cargo-fuzz 官方安装说明](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)
准备 nightly、cargo-fuzz 和本机 C++ 编译器。不要改变产品工具链文件。
在仓库根目录运行：

```sh
mkdir -p fuzz/corpus/gp_boundary fuzz/artifacts/gp_boundary
cargo +nightly-2026-11-10 fuzz run --no-cfg-fuzzing gp_boundary \
  fuzz/corpus/gp_boundary fuzz/seeds/gp_boundary -- \
  -dict=fuzz/gp.dict -max_total_time=120 -timeout=5 \
  -rss_limit_mb=1024 -max_len=16384 -seed=20261111 \
  -artifact_prefix=fuzz/artifacts/gp_boundary/ -print_final_stats=1
```

第一个语料目录可写，第二个作为固定种子；生成语料和 crash artifacts 不纳入
Git。`--no-cfg-fuzzing` 保留被测依赖正常代码路径。cargo-fuzz 默认启用
AddressSanitizer、覆盖率插桩、debug assertions 和 overflow checks。
开发锁文件保留产品锁中的包版本、来源和校验和；libFuzzer 会额外启用
开发图中的 `cc` 并行构建依赖，不改变产品图。

固定随机种子不能保证不同 CPU、工具链或时间预算下生成完全相同的语料。
发现失败后保留并最小化输入，添加稳定回归；不要仅重跑到成功。
`cov`/`ft` 是 libFuzzer 的边与特征计数，不是源码覆盖百分比。

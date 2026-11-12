# Independent TCP test peer

This is a development-only gVisor TCP echo peer. The Rust product does not link,
launch, or ship this Go program. Its only transport is length-prefixed IP packets
on stdin/stdout. `channel.New` and `Stack.CreateNIC` create in-process objects;
there is no TUN, host network interface, host socket, container, or OS route setup.

The peer pins gVisor `v0.0.0-20261106024050-6e980c2ddc1e` in `go.mod`/`go.sum`.
Build from the repository root with Go 1.27.3 (the first build may download the
official Go toolchain and checksummed modules):

```sh
mkdir -p target
(
  cd tests/interop/gvisor
  GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -mod=readonly -trimpath -o ../../../target/gvisor-peer .
)
GP_PROXY_GVISOR_PEER="$PWD/target/gvisor-peer" cargo test --locked --test gvisor_interop -- --ignored --nocapture --test-threads=1
```

Once cached, set `GOPROXY=off` for the Go build and add `--offline` to Cargo.
The test is explicitly ignored by the normal Rust suite; an absent peer binary
is an error when the opt-in test runs, never a successful skip.

Each of three scenarios runs four concurrent 256 KiB streams and four short
streams including an empty half-close. The peer has a fixed 16 KiB TCP receive
buffer and delays its first application read by 350 ms. One Rust reader waits
for an actual zero-window advertisement before it starts draining. The test
requires observed zero windows in both directions, byte equality, EOF, and
successful child exit. Two scenarios additionally inject first-SYN loss,
periodic loss, duplication, delay, and real reordering. These seeds configure
packet impairments; OS/thread scheduling is not deterministic.

The bridge packet queues are bounded at 64 packets / 1400 bytes, peer application
concurrency at eight, peer lifetime at two minutes, and each Rust scenario at
70 seconds plus bounded cleanup. Diagnostics are capped at 64 KiB. Child
environment is cleared. The harness cancels and joins tasks, explicitly waits
for the peer, and kills/waits on startup failure or shutdown timeout. The Go
peer is a one-shot test process; it is not a production daemon.

gVisor and `github.com/google/btree` use Apache-2.0; `golang.org/x/{exp,sys,time}`
use BSD-3-Clause. These five modules were checked against the actual build graph
and their cached root LICENSE files. We wrote the adapter against public APIs;
no go-ocproxy source was copied. This helper binary is excluded from the product
preview. Any future distribution of it needs its own Go/toolchain and dependency
license bundle; the Rust product's bundle does not cover it.

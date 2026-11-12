#!/usr/bin/env node
// Execute the actual CLI-generated PAC in a JS context with no DNS helpers.
// All destinations and files are synthetic; no gateway connection is made.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');

const binary = path.resolve(process.argv[2] || 'target/debug/gp-proxy' + (process.platform === 'win32' ? '.exe' : ''));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-pac-js-'));
const proxy = 'PROXY 127.0.0.1:8080';
let assertions = 0;
try {
  const config = path.join(directory, 'proxy.toml');
  const history = path.join(directory, 'proxy.pac-history.json');
  fs.writeFileSync(history, JSON.stringify({
    version: 1,
    domains: ['retired.corp.test'], networks: [],
    gateway_domains: [
      { kind: 'exact', domain: 'jira.corp.test' },
      { kind: 'subdomains', domain: 'svc.corp.test' },
    ],
  }), { mode: 0o600 });

  function load(networks) {
    fs.writeFileSync(config, "gateway = 'https://vpn.example.invalid'\ndomains = ['local.corp.test']\nnetworks = " + JSON.stringify(networks) + '\n');
    const script = execFileSync(binary, ['--config', config, 'pac'], { encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
    assert(!/\b(isInNet|isResolvable|dnsResolve|myIpAddress)\s*\(/.test(script));
    assert(!script.includes('; DIRECT'));
    const context = vm.createContext({ dnsDomainIs: (host, suffix) => host.endsWith(suffix) });
    vm.runInContext(script, context, { timeout: 1000 });
    return host => {
      context.inputHost = host;
      return vm.runInContext('FindProxyForURL("https://synthetic.test/", inputHost)', context, { timeout: 1000 });
    };
  }
  function check(classify, host, expected) {
    assert.equal(classify(host), expected, host);
    assertions += 1;
  }
  const classify = load(['10.0.0.0/8', '192.0.2.128/25', '203.0.113.7/32', '240.0.0.0/4', 'fd00::/8']);
  for (const host of [
    'local.corp.test', 'a.local.corp.test', 'retired.corp.test', 'a.retired.corp.test',
    'JIRA.CORP.TEST.', 'a.svc.corp.test', 'a.b.svc.corp.test',
    '10.0.0.0', '10.255.255.255', '192.0.2.128', '192.0.2.255', '203.0.113.7',
    '240.0.0.0', '255.255.255.255', 'fd12::1', '2001:db8::1', '[fd12::1]',
    '010.0.0.1', '999.1.2.3', '2130706433', '10.1', '10..1.2',
  ]) check(classify, host, proxy);
  for (const host of [
    'public.example', 'a.jira.corp.test', 'svc.corp.test', 'evilsvc.corp.test',
    'jira.corp.test.evil', 'evillocal.corp.test', '9.255.255.255', '11.0.0.0',
    '192.0.2.127', '192.0.3.0', '203.0.113.6', '203.0.113.8', '239.255.255.255',
  ]) check(classify, host, 'DIRECT');
  // Independent arithmetic oracle across deterministic random canonical literals.
  let state = 0x1729;
  for (let i = 0; i < 4096; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const octets = [state >>> 24, (state >>> 16) & 255, (state >>> 8) & 255, state & 255];
    const corporate = octets[0] === 10 || octets[0] >= 240
      || (octets[0] === 192 && octets[1] === 0 && octets[2] === 2 && octets[3] >= 128)
      || octets.join('.') === '203.0.113.7';
    check(classify, octets.join('.'), corporate ? proxy : 'DIRECT');
  }
  const all = load(['0.0.0.0/0']);
  for (const host of ['0.0.0.0', '127.0.0.1', '128.0.0.1', '255.255.255.255']) check(all, host, proxy);
  check(all, 'public.example', 'DIRECT');
  check(all, 'fd00::1', 'DIRECT');
  // IPv4-mapped IPv6 reaches an IPv4 destination. Exercise the actual PAC
  // without an IPv6 rule, which would otherwise hide a DIRECT classification.
  // WHATWG URL normalization independently supplies the browser's hex spelling.
  function mappedHosts(classify, ipv4, expected) {
    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    const hosts = [
      `::ffff:${ipv4}`, `::ffff:${high}:${low}`, `0:0:0:0:0:ffff:${high}:${low}`,
      `0000:0000:0000:0000:0000:FFFF:${high.padStart(4, '0')}:${low.padStart(4, '0')}`,
      `0:0:0::ffff:${ipv4}`,
    ];
    for (const host of hosts) {
      check(classify, host, expected);
      check(classify, `[${host}]`, expected);
      check(classify, new URL(`https://[${host}]/`).hostname, expected);
    }
  }
  const ipv4Only = load(['10.0.0.0/8', '192.0.2.128/25', '203.0.113.7/32']);
  for (const ip of ['10.0.0.0', '10.1.2.3', '10.255.255.255', '192.0.2.128', '192.0.2.255', '203.0.113.7']) {
    mappedHosts(ipv4Only, ip, proxy);
  }
  for (const ip of ['0.0.0.0', '8.8.8.8', '9.255.255.255', '11.0.0.0', '192.0.2.127', '192.0.3.0', '203.0.113.8', '255.255.255.255']) {
    mappedHosts(ipv4Only, ip, 'DIRECT');
  }
  for (const host of ['fd00::1', '[2001:db8::1]', '::a01:203', '[::10.1.2.3]']) {
    check(ipv4Only, host, 'DIRECT');
  }
  // Compression after FFFF is also legal when the embedded IPv4 has zeros.
  for (const host of ['0:0:0:0:0:ffff::', '[0:0:0:0:0:ffff::1]']) check(all, host, proxy);
  const mappedRule = load(['::ffff:10.0.0.0/104']);
  check(mappedRule, '10.1.2.3', proxy);
  mappedHosts(mappedRule, '10.1.2.3', proxy);
  mappedHosts(mappedRule, '11.0.0.0', 'DIRECT');
  check(mappedRule, '2001:db8::1', 'DIRECT');
  const ipv6Only = load(['::/0']);
  // Broad IPv6 authorization must not silently become an IPv4 grant.
  check(ipv6Only, '10.1.2.3', 'DIRECT');
  mappedHosts(ipv6Only, '10.1.2.3', 'DIRECT');
  check(ipv6Only, '2001:db8::1', proxy);
  // Every explicit mapped CIDR /96..128 has IPv4 /0..32 semantics. Use
  // arithmetic boundaries rather than duplicating the PAC's bitwise matcher.
  function dotted(value) {
    return [Math.floor(value / 2 ** 24), Math.floor(value / 2 ** 16) % 256,
      Math.floor(value / 256) % 256, value % 256].join('.');
  }
  const sample = 203 * 2 ** 24 + 113 * 256 + 129;
  for (let prefix = 0; prefix <= 32; prefix++) {
    const classifyPrefix = load([`::ffff:203.0.113.129/${prefix + 96}`]);
    const size = 2 ** (32 - prefix), first = Math.floor(sample / size) * size, last = first + size - 1;
    for (const value of new Set([first, last, first - 1, last + 1])) {
      if (value < 0 || value > 2 ** 32 - 1) continue;
      const host = dotted(value), expected = value >= first && value <= last ? proxy : 'DIRECT';
      check(classifyPrefix, host, expected);
      check(classifyPrefix, `::ffff:${host}`, expected);
      check(classifyPrefix, new URL(`https://[::ffff:${host}]/`).hostname, expected);
    }
    check(classifyPrefix, '2001:db8::1', 'DIRECT');
  }
  // Malformed text must not be accepted as a mapped IPv4 by the PAC parser.
  // These raw host arguments do not assert that a browser accepts such URLs.
  for (const host of [
    '::ffff:010.1.2.3', '::ffff:256.1.2.3', '::ffff:10.1.2', '::ffff:10.1.2.3:4',
    '::ffff:10.1.2.3::', ':::ffff:a01:203', '::ffff:00000:203', '::ffff:a01:203%1',
    '::ffff:a01:203\n', '::ffff:a01:203\0', '[::ffff:a01:203', '::ffff:a01:203]',
    '0:0:0:0:0:ffff:a01:203:0', '00000:0000:0000:0000:0000:ffff:a01:203',
  ]) check(all, host, 'DIRECT');
  // A URL parser may remove ASCII newlines before invoking PAC. Its actual
  // canonical host still has to retain the corporate IPv4 classification.
  check(ipv4Only, new URL('https://[::ffff:a01:203\n]/').hostname, proxy);
  check(ipv4Only, '0:0:0:0:0:ffff:a00::', proxy);
  const boundary = load(['128.0.0.0/1', '192.0.2.2/31']);
  check(boundary, '127.255.255.255', 'DIRECT');
  check(boundary, '128.0.0.0', proxy);
  const pair = load(['192.0.2.2/31']);
  for (const host of ['192.0.2.2', '192.0.2.3']) check(pair, host, proxy);
  for (const host of ['192.0.2.1', '192.0.2.4']) check(pair, host, 'DIRECT');
  console.log(`PAC JavaScript: ${assertions} classification checks passed; DNS helpers unavailable.`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}

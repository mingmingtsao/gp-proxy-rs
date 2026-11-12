#!/usr/bin/env node
'use strict';
// Opt-in API experiment or product Refresh button validation. All targets
// and services are synthetic loopback; only owned temporary profiles are used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const options = new Map();
for (let i = 2; i < process.argv.length; i++) {
  const key = process.argv[i];
  if (key === '--run' || key === '--product') options.set(key, true);
  else {
    assert(['--binary', '--playwright-core', '--output'].includes(key) && process.argv[i + 1], 'unknown option');
    options.set(key, process.argv[++i]);
  }
}
if (!options.has('--run')) {
  console.log('Opt-in: node scripts/tests/check-browser-pac-refresh.cjs --run [--product] --binary PATH --playwright-core PATH --output PATH');
  process.exit(0);
}
const binary = path.resolve(options.get('--binary') || 'target/debug/gp-proxy');
const output = path.resolve(options.get('--output') || '/tmp/browser-pac-refresh.json');
const modulePath = options.get('--playwright-core') || 'playwright-core';
const { chromium } = require(modulePath);
const playwright = require(path.join(path.dirname(require.resolve(modulePath)), 'package.json')).version;
const productMode = options.has('--product');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-pac-refresh-'));
const extension = path.resolve(__dirname, '../../integrations/chromium-pac');
const results = [];
const events = [];
const hits = { proxy: [], direct: [], pac: [] };
let context, worker, extensionId, browserVersion, pacBody = '', sequence = 0, infrastructureError, deadlineHit = false;
let holdPac = false;
const heldPac = [];
const heldOrigin = [];
const documents = [];
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function respond(response, body) {
  response.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(body), 'Connection': 'close', 'Cache-Control': 'no-store' });
  response.end(body);
}
const proxy = http.createServer((request, response) => {
  const url = new URL(request.url);
  hits.proxy.push({ host: url.hostname, path: url.pathname });
  respond(response, 'SYNTHETIC_PROXY');
});
proxy.on('connect', (_, socket) => socket.end('HTTP/1.1 502 Synthetic only\r\nConnection: close\r\n\r\n'));
const origin = http.createServer((request, response) => {
  const url = new URL(request.url, 'http://' + request.headers.host);
  hits.direct.push({ host: url.hostname, path: url.pathname });
  if (url.pathname.includes('inflight_before_refresh')) heldOrigin.push(response);
  else respond(response, 'SYNTHETIC_DIRECT');
});
const pac = http.createServer((request, response) => {
  hits.pac.push({ path: request.url, sha256: hash(pacBody), held: holdPac });
  if (holdPac) heldPac.push({ response, body: pacBody });
  else respond(response, pacBody);
});
const servers = [proxy, origin, pac];
async function listen(server, port = 0) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  return server.address().port;
}
async function close(server) {
  server.closeAllConnections();
  if (server.listening) await new Promise(resolve => server.close(resolve));
}
async function until(predicate, label, budget = 5000) {
  const deadline = Date.now() + budget;
  while (!predicate()) {
    assert(Date.now() < deadline, 'timeout: ' + label);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}
async function visit(name, host, port) {
  const token = '/case-' + name + '-' + (++sequence);
  const page = await context.newPage();
  let body = null, error = null;
  try {
    await page.goto('http://' + host + ':' + port + token, { waitUntil: 'domcontentloaded', timeout: 8000 });
    body = await page.locator('body').innerText({ timeout: 1000 });
  } catch (failure) { error = String(failure.message).split('\n')[0]; }
  finally { await page.close(); }
  const result = { name, host, proxy: hits.proxy.filter(h => h.path === token).length, direct: hits.direct.filter(h => h.path === token).length, body, error };
  results.push(result);
  return result;
}
async function setPac(url) {
  if (productMode && url.includes('?')) {
    const before = await worker.evaluate(() => new Promise(resolve => chrome.proxy.settings.get({ incognito: false }, resolve)));
    const page = await context.newPage();
    try {
      await page.goto('chrome-extension://' + extensionId + '/popup.html');
      await page.locator('#refresh').click({ timeout: 5000 });
      await page.waitForFunction(() => document.querySelector('#notice').textContent.includes('已请求刷新'), null, { timeout: 5000 });
    } finally { await page.close(); }
    const after = await worker.evaluate(() => new Promise(resolve => chrome.proxy.settings.get({ incognito: false }, resolve)));
    assert.equal(after.levelOfControl, 'controlled_by_this_extension');
    assert.equal(after.value.pacScript.mandatory, true);
    assert.notEqual(after.value.pacScript.url, before.value.pacScript.url);
    assert(after.value.pacScript.url.startsWith(url.split('?')[0] + '?gpv='));
    assert.match(after.value.pacScript.url.split('?')[1], /^gpv=[0-9a-f]{32}$/);
    events.push({ operation: 'explicit product popup Refresh click', after });
    return;
  }
  // The unchanged-URL negative control deliberately uses the browser API.
  // Research mode also uses the API for version changes; product mode above
  // must go through the real user-facing Refresh button.
  const event = await worker.evaluate(async url => {
    const get = () => new Promise(resolve => chrome.proxy.settings.get({ incognito: false }, resolve));
    const before = await get();
    if (before.levelOfControl !== 'controlled_by_this_extension' || before.value.pacScript?.mandatory !== true) throw new Error('not owned mandatory PAC');
    await new Promise((resolve, reject) => chrome.proxy.settings.set({ scope: 'regular', value: { mode: 'pac_script', pacScript: { url, mandatory: true } } },
      () => chrome.runtime.lastError ? reject(new Error('set failed')) : resolve()));
    const after = await get();
    if (after.levelOfControl !== 'controlled_by_this_extension' || after.value.pacScript?.mandatory !== true || after.value.pacScript.url !== url) throw new Error('setting did not take effect');
    return { after };
  }, url);
  events.push({ operation: 'set mandatory PAC directly without clear', ...event });
}
function assertProxy(result) { assert(result.proxy > 0 && result.direct === 0 && result.body === 'SYNTHETIC_PROXY', JSON.stringify(result)); }
function assertBlocked(result) { assert(result.proxy === 0 && result.direct === 0 && /ERR_MANDATORY_PROXY_CONFIGURATION_FAILED/.test(result.error || ''), JSON.stringify(result)); }
const watchdog = setTimeout(() => {
  deadlineHit = true;
  context?.close().catch(() => {});
  for (const server of servers) server.closeAllConnections();
}, 90000);
watchdog.unref();
(async () => {
  try {
    const proxyPort = await listen(proxy), originPort = await listen(origin), pacPort = await listen(pac);
    function productPac(domains) {
      const config = path.join(directory, 'synthetic-' + documents.length + '.toml');
      fs.writeFileSync(config, 'gateway = "https://vpn.example.invalid"\nhttp_listen = "127.0.0.1:' + proxyPort + '"\nsocks_listen = "127.0.0.1:1"\ntrust_gateway_routes = false\nnetworks = []\ndomains = ' + JSON.stringify(domains) + '\n', { mode: 0o600 });
      const body = execFileSync(binary, ['--config', config, 'pac'], { encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
      assert(!body.includes('; DIRECT'));
      documents.push({ domains, sha256: hash(body) });
      return body;
    }
    const oldPac = productPac(['corp.test']);
    const expandedPac = productPac(['corp.test', 'newcorp.test']);
    const finalPac = productPac(['corp.test', 'newcorp.test', 'latecorp.test']);
    pacBody = oldPac;
    const profile = path.join(directory, 'profile');
    fs.mkdirSync(path.join(profile, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(profile, 'Default', 'Preferences'), JSON.stringify({ dns_over_https: { mode: 'off' }, credentials_enable_service: false, profile: { password_manager_enabled: false } }));
    context = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', headless: true, chromiumSandbox: true, timeout: 20000, ignoreDefaultArgs: ['--disable-extensions'], serviceWorkers: 'block', acceptDownloads: false,
      args: ['--no-proxy-server', '--enable-unsafe-extension-debugging', '--host-resolver-rules=MAP * 127.0.0.1', '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--disable-sync', '--disable-client-side-phishing-detection', '--safebrowsing-disable-auto-update', '--no-first-run', '--no-default-browser-check', '--disable-features=DnsOverHttps,MediaRouter,OptimizationHints,AutofillServerCommunication'],
    });
    browserVersion = context.browser().version();
    const cdp = await context.browser().newBrowserCDPSession();
    const installed = await cdp.send('Extensions.loadUnpacked', { path: extension });
    extensionId = installed.id;
    await cdp.detach();
    worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 10000 });
    await worker.evaluate(() => {
      globalThis.settingEvents = [];
      chrome.proxy.settings.onChange.addListener(setting => globalThis.settingEvents.push({ mode: setting.value.mode, mandatory: setting.value.pacScript?.mandatory, url: setting.value.pacScript?.url }));
    });
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.protocol === 'chrome-extension:' && url.hostname === installed.id) return route.continue();
      if (url.protocol === 'http:' && ['corp.test', 'newcorp.test', 'latecorp.test', 'public.test'].includes(url.hostname)) return route.continue();
      return route.abort('blockedbyclient');
    });
    const baseUrl = 'http://127.0.0.1:' + pacPort + '/proxy.pac';
    const versionedUrl = n => baseUrl + '?gpv=' + String(n).padStart(32, '0');
    const page = await context.newPage();
    await page.goto('chrome-extension://' + installed.id + '/popup.html');
    await page.locator('#pac-url').fill(baseUrl);
    await page.locator('#enable').click();
    await page.waitForFunction(() => document.querySelector('#status').dataset.enabled === 'true', null, { timeout: 5000 });
    await page.close();
    assertProxy(await visit('known_corp_before_refresh', 'corp.test', originPort));
    assert.equal((await visit('new_domain_old_pac_direct_control', 'newcorp.test', originPort)).direct, 1);

    pacBody = expandedPac;
    const fetchesBeforeSameUrl = hits.pac.length;
    await setPac(baseUrl);
    assert.equal((await visit('same_url_set_still_stale', 'newcorp.test', originPort)).direct, 1);
    assert.equal(hits.pac.length, fetchesBeforeSameUrl, 'same URL unexpectedly triggered a fetch; update the research conclusion');

    holdPac = true;
    await setPac(versionedUrl(1));
    await until(() => heldPac.length > 0, 'versioned PAC fetch');
    const beforeHeld = { proxy: hits.proxy.length, direct: hits.direct.length };
    let completedWhileHeld = 0;
    const waiting = ['newcorp.test', 'corp.test', 'public.test'].map(host => visit('waiting_for_new_pac', host, originPort).then(value => { completedWhileHeld++; return value; }));
    await new Promise(resolve => setTimeout(resolve, 250));
    events.push({ operation: 'requests during held PAC response', completed: completedWhileHeld, proxy: hits.proxy.length - beforeHeld.proxy, direct: hits.direct.length - beforeHeld.direct });
    assert.equal(completedWhileHeld, 0);
    assert.equal(hits.proxy.length, beforeHeld.proxy);
    assert.equal(hits.direct.length, beforeHeld.direct);
    holdPac = false;
    for (const held of heldPac.splice(0)) respond(held.response, held.body);
    const released = await Promise.all(waiting);
    assertProxy(released[0]); assertProxy(released[1]); assert.equal(released[2].direct, 1);

    const inflight = visit('inflight_before_refresh', 'latecorp.test', originPort);
    await until(() => heldOrigin.length > 0, 'existing direct request at origin');
    pacBody = finalPac;
    await setPac(versionedUrl(2));
    assertProxy(await visit('new_request_after_second_refresh', 'latecorp.test', originPort));
    for (const held of heldOrigin.splice(0)) if (!held.destroyed) respond(held, 'SYNTHETIC_DIRECT');
    const priorRequest = await inflight;
    events.push({ operation: 'already dispatched direct request after refresh', result: priorRequest });

    await close(pac);
    await setPac(versionedUrl(3));
    assertBlocked(await visit('refresh_endpoint_unreachable_new_domain', 'newcorp.test', originPort));
    assertBlocked(await visit('refresh_endpoint_unreachable_known_domain', 'corp.test', originPort));
    pacBody = 'invalid PAC }';
    await listen(pac, pacPort);
    await setPac(versionedUrl(4));
    assertBlocked(await visit('refresh_invalid_pac', 'newcorp.test', originPort));
    pacBody = finalPac;
    await setPac(versionedUrl(5));
    assertProxy(await visit('refresh_recovery', 'newcorp.test', originPort));
    const changes = await worker.evaluate(() => globalThis.settingEvents);
    assert(changes.length >= 5 && changes.every(change => change.mode === 'pac_script' && change.mandatory === true));
    events.push({ operation: 'browser setting notifications', changes });
  } catch (error) { infrastructureError = String(error.stack || error); }
  finally {
    clearTimeout(watchdog);
    if (context) await context.close().catch(() => {});
    await Promise.all(servers.map(close));
    const report = { audit: productMode ? 'product extension explicit Refresh button with mandatory PAC; unchanged-URL API negative control' : 'research-only versioned mandatory PAC replacement via browser API', browser: browserVersion, playwright, product_binary_sha256: hash(fs.readFileSync(binary)), extension_sha256: Object.fromEntries(fs.readdirSync(extension).sort().map(file => [file, hash(fs.readFileSync(path.join(extension, file)))])), pac_documents: documents, results, events, pac_fetches: hits.pac, restart_validated: false, deadline_hit: deadlineHit, infrastructure_error: infrastructureError || null };
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report, null, 2));
    fs.rmSync(directory, { recursive: true, force: true });
    process.exitCode = infrastructureError || deadlineHit ? 1 : 0;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

#!/usr/bin/env node
'use strict';
// Opt-in browser behavior audit. Uses only owned temporary profiles and localhost
// services; never loads user browser profiles, real credentials, or a GP gateway.
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
  if (key === '--run' || key === '--mandatory' || key === '--native-install') options.set(key, true);
  else {
    if (!['--binary', '--playwright-core', '--output'].includes(key) || !process.argv[i + 1]) {
      throw new Error('Unknown or incomplete option; use --run --binary PATH --playwright-core PATH --output PATH');
    }
    options.set(key, process.argv[++i]);
  }
}
if (!options.has('--run')) {
  console.log('Opt-in: node scripts/tests/check-browser-pac.cjs --run [--mandatory [--native-install]] --binary PATH --playwright-core PATH --output PATH');
  process.exit(0);
}
const binary = path.resolve(options.get('--binary') || 'target/debug/gp-proxy');
const output = path.resolve(options.get('--output') || 'browser-pac-default.json');
const modulePath = options.get('--playwright-core') || 'playwright-core';
const { chromium } = require(modulePath);
const playwrightVersion = require(path.join(path.dirname(require.resolve(modulePath)), 'package.json')).version;
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-browser-pac-'));
const mandatory = options.has('--mandatory');
const nativeInstall = options.has('--native-install');
assert(!nativeInstall || mandatory, '--native-install requires --mandatory');
const extension = path.resolve(__dirname, '../../integrations/chromium-pac');
const contexts = new Set();
const workers = new Map();
const profiles = new Map();
let extensionId;
const settingsObservations = [];
const proxyHits = [];
const directHits = [];
const pacHits = [];
const results = [];
let pacMode = 'valid';
let generatedPac = '';
let sequence = 0;
let browserVersion;
let infrastructureError;
let deadlineHit = false;

function respond(response, body, type = 'text/plain', status = 200) {
  response.writeHead(status, {
    'Content-Type': type,
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Connection': 'close',
  });
  response.end(body);
}
function requestUrl(request) {
  return new URL(request.url, 'http://' + request.headers.host);
}
const proxy = http.createServer((request, response) => {
  const url = requestUrl(request);
  proxyHits.push({ host: url.hostname, path: url.pathname });
  respond(response, 'SYNTHETIC_PROXY');
});
proxy.on('connect', (_request, socket) => { socket.end('HTTP/1.1 502 Synthetic test only\r\nConnection: close\r\n\r\n'); });
const origin = http.createServer((request, response) => {
  const url = requestUrl(request);
  directHits.push({ host: url.hostname, path: url.pathname });
  respond(response, 'SYNTHETIC_DIRECT_ORIGIN');
});
const pac = http.createServer((request, response) => {
  pacHits.push({ path: request.url, mode: pacMode });
  const body = pacMode === 'valid' ? generatedPac : generatedPac + '\n} deliberately invalid PAC syntax';
  respond(response, body, 'application/x-ns-proxy-autoconfig');
});
const servers = [proxy, origin, pac];
async function listen(server, port = 0) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  return server.address().port;
}
async function closeServer(server) {
  server.closeAllConnections();
  if (server.listening) await new Promise(resolve => server.close(resolve));
}
async function closeContext(context) {
  await context.close();
  contexts.delete(context);
  workers.delete(context);
}
async function readSetting(context) {
  return workers.get(context).evaluate(() => new Promise(resolve => chrome.proxy.settings.get({ incognito: false }, resolve)));
}
async function popup(context) {
  const page = await context.newPage();
  await page.goto('chrome-extension://' + extensionId + '/popup.html');
  await page.waitForFunction(() => document.querySelector('#status')?.dataset.enabled !== undefined, null, { timeout: 5000 });
  return page;
}
async function freshBrowser(pacPort, existingProfile) {
  const profile = existingProfile || path.join(directory, 'profile-' + (++sequence));
  if (!existingProfile) {
    fs.mkdirSync(path.join(profile, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(profile, 'Default', 'Preferences'), JSON.stringify({
      dns_over_https: { mode: 'off' },
      extensions: { ui: { developer_mode: true } },
      credentials_enable_service: false,
      profile: { password_manager_enabled: false },
    }));
  }
  // Chromium cannot disable implicit loopback PAC bypass. A non-local .test
  // hostname avoids that rule; only this process maps its destination to 127/8.
  // Baseline proxy/direct counters below prove this distinction in the engine.
  const context = await chromium.launchPersistentContext(profile, {
    headless: !nativeInstall,
    channel: 'chromium',
    chromiumSandbox: true,
    // Restore ordinary extension preference loading in this isolated profile.
    // Command-line/CDP extension loaders are deliberately nonpersistent in
    // Chromium. The optional native mode waits for ordinary Load unpacked.
    ignoreDefaultArgs: mandatory ? ['--disable-extensions'] : [],
    timeout: 20000,
    serviceWorkers: 'block',
    acceptDownloads: false,
    args: [
      ...(mandatory ? ['--no-proxy-server', ...(!nativeInstall ? ['--enable-unsafe-extension-debugging'] : [])]
        : ['--proxy-pac-url=http://127.0.0.1:' + pacPort + '/proxy.pac']),
      '--host-resolver-rules=MAP * 127.0.0.1',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-default-apps',
      '--disable-sync',
      '--disable-client-side-phishing-detection',
      '--safebrowsing-disable-auto-update',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-features=DnsOverHttps,MediaRouter,OptimizationHints,AutofillServerCommunication',
    ],
  });
  contexts.add(context);
  profiles.set(context, profile);
  browserVersion = context.browser().version();
  if (mandatory) {
    if (!existingProfile) {
      if (nativeInstall) {
        const manager = await context.newPage();
        await manager.goto('chrome://extensions');
        console.error('Install only in this temporary Chrome for Testing window: Load unpacked -> ' + extension);
        const installed = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 60000 });
        extensionId = new URL(installed.url()).host;
        await manager.close();
      } else {
        const cdp = await context.browser().newBrowserCDPSession();
        const installed = await cdp.send('Extensions.loadUnpacked', { path: extension });
        extensionId = installed.id;
        await cdp.detach();
      }
    }
    // On restart the worker can be dormant; opening our own local popup wakes
    // it only to read status. No test code sets or clears the proxy setting.
    let page;
    if (existingProfile) page = await popup(context);
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 10000 });
    workers.set(context, worker);
    extensionId = new URL(worker.url()).host;
    const before = await readSetting(context);
    if (!existingProfile) {
      assert.equal(before.value.mode, 'direct', 'extension changed settings without a click');
      assert.equal(before.levelOfControl, 'controllable_by_this_extension');
      page = await popup(context);
      await page.locator('#pac-url').fill('http://127.0.0.1:' + pacPort + '/proxy.pac');
      await page.locator('#enable').click();
      await page.waitForFunction(() => document.querySelector('#status').dataset.enabled === 'true');
    } else {
      assert.equal(before.levelOfControl, 'controlled_by_this_extension');
      assert.equal(before.value.pacScript?.mandatory, true);
      assert.equal(before.value.pacScript?.url, 'http://127.0.0.1:' + pacPort + '/proxy.pac');
    }
    const after = await readSetting(context);
    assert.equal(after.levelOfControl, 'controlled_by_this_extension');
    assert.equal(after.value.pacScript?.mandatory, true);
    settingsObservations.push({ phase: existingProfile ? 'restart_without_click' : 'explicit_popup_enable', before, after });
    await page.close();
  }
  // Web-visible requests are restricted too. PAC downloads are below this API
  // and use the fixed numeric localhost URL supplied above.
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (mandatory && url.protocol === 'chrome-extension:' && url.hostname === extensionId) return route.continue();
    if (url.protocol === 'http:' && ['corp.test', 'public.test'].includes(url.hostname)) return route.continue();
    return route.abort('blockedbyclient');
  });
  return context;
}
async function visit(context, name, originPort, host = 'corp.test') {
  const token = '/case-' + name + '-' + (++sequence);
  const beforePac = pacHits.length;
  const page = await context.newPage();
  let error = null;
  let body = null;
  try {
    await page.goto('http://' + host + ':' + originPort + token, { waitUntil: 'domcontentloaded', timeout: 10000 });
    body = await page.locator('body').innerText({ timeout: 2000 });
  } catch (failure) {
    error = String(failure.message).split('\n')[0];
  } finally { await page.close(); }
  const result = {
    name, host, proxy: proxyHits.filter(hit => hit.path === token).length,
    direct: directHits.filter(hit => hit.path === token).length,
    pac_fetches_during_navigation: pacHits.length - beforePac,
    body, error,
  };
  results.push(result);
  return result;
}

const watchdog = setTimeout(() => {
  deadlineHit = true;
  for (const context of contexts) context.close().catch(() => {});
  for (const server of servers) server.closeAllConnections();
}, nativeInstall ? 300000 : 120000);
watchdog.unref();

(async () => {
  try {
    const proxyPort = await listen(proxy);
    const originPort = await listen(origin);
    const pacPort = await listen(pac);
    const config = path.join(directory, 'synthetic.toml');
    fs.writeFileSync(config, [
      'gateway = "https://vpn.example.invalid"',
      'http_listen = "127.0.0.1:' + proxyPort + '"',
      'socks_listen = "127.0.0.1:1"',
      'domains = ["corp.test"]',
      'networks = []',
      'trust_gateway_routes = false',
    ].join('\n') + '\n', { mode: 0o600 });
    generatedPac = execFileSync(binary, ['--config', config, 'pac'], {
      encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024,
    });
    assert(!generatedPac.includes('; DIRECT'), 'corporate proxy must have no DIRECT alternate');
    assert(generatedPac.includes('PROXY 127.0.0.1:' + proxyPort));

    let context = await freshBrowser(pacPort);
    const baseline = await visit(context, 'valid_pac_proxy_available', originPort);
    assert(baseline.proxy > 0 && baseline.direct === 0 && baseline.body === 'SYNTHETIC_PROXY',
      'PAC/proxy baseline failed; cannot draw fallback conclusions');
    const control = await visit(context, 'explicit_direct_public_control', originPort, 'public.test');
    assert(control.direct > 0 && control.proxy === 0 && control.body === 'SYNTHETIC_DIRECT_ORIGIN',
      'direct origin control failed; cannot detect a DIRECT fallback');

    if (nativeInstall) {
      const profile = profiles.get(context);
      await closeContext(context);
      context = await freshBrowser(pacPort, profile);
      const restarted = await visit(context, 'same_profile_restart_keeps_mandatory_pac', originPort);
      assert(restarted.proxy > 0 && restarted.direct === 0, 'restart lost the effective PAC setting');
    }

    await closeServer(proxy);
    const stopped = await visit(context, 'cached_pac_proxy_stopped', originPort);
    assert.equal(stopped.direct, 0);
    assert.match(stopped.error || '', /ERR_PROXY_CONNECTION_FAILED/);
    await listen(proxy, proxyPort);
    await closeServer(pac);
    const cached = await visit(context, 'cached_pac_endpoint_stopped_proxy_available', originPort);
    assert(cached.proxy > 0 && cached.direct === 0, 'valid cached PAC did not remain effective');
    await closeContext(context);

    context = await freshBrowser(pacPort);
    const unreachable = await visit(context, 'fresh_profile_pac_unreachable', originPort);
    if (mandatory) {
      assert.equal(unreachable.direct, 0);
      assert.match(unreachable.error || '', /ERR_MANDATORY_PROXY_CONFIGURATION_FAILED/);
    } else assert(unreachable.direct > 0 && unreachable.proxy === 0);
    await closeContext(context);

    pacMode = 'invalid';
    await listen(pac, pacPort);
    context = await freshBrowser(pacPort);
    const invalid = await visit(context, 'fresh_profile_pac_invalid', originPort);
    if (mandatory) {
      assert.equal(invalid.direct, 0);
      assert.match(invalid.error || '', /ERR_MANDATORY_PROXY_CONFIGURATION_FAILED/);
    } else assert(invalid.direct > 0 && invalid.proxy === 0);
    if (mandatory) {
      const page = await popup(context);
      await page.locator('#disable').click();
      await page.waitForFunction(() => document.querySelector('#status').dataset.enabled === 'false');
      const afterClear = await readSetting(context);
      await page.close();
      settingsObservations.push({ after_clear: afterClear });
      assert.equal(afterClear.value.mode, 'direct', 'clear did not restore the deliberate CLI-direct underlay');
      const restored = await visit(context, 'explicit_extension_clear_restores_underlay', originPort);
      assert(restored.direct > 0 && restored.proxy === 0, 'clear did not restore direct underlay behavior');
    }
    await closeContext(context);
  } catch (error) { infrastructureError = String(error.stack || error); }
  finally {
    clearTimeout(watchdog);
    await Promise.allSettled([...contexts].map(context => closeContext(context)));
    await Promise.all(servers.map(closeServer));
    const unexpectedDirect = results.filter(result => result.host === 'corp.test'
      && result.name !== 'explicit_extension_clear_restores_underlay' && result.direct > 0).map(result => result.name);
    const report = {
      audit: mandatory ? 'product MV3 extension via explicit popup clicks; mandatory=true PAC; CLI direct underlay' : 'default Chromium CLI PAC behavior; no mandatory configuration',
      installation: nativeInstall ? 'native Load unpacked in owned temporary profile' : mandatory ? 'CDP temporary installation; removed by Chromium on restart' : 'none',
      restart_validated: nativeInstall && results.some(result => result.name === 'same_profile_restart_keeps_mandatory_pac' && result.proxy > 0),
      browser: browserVersion, playwright: playwrightVersion,
      product_binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
      generated_pac_sha256: crypto.createHash('sha256').update(generatedPac).digest('hex'),
      extension_sha256: mandatory ? Object.fromEntries(fs.readdirSync(extension).sort().map(file => [file, crypto.createHash('sha256').update(fs.readFileSync(path.join(extension, file))).digest('hex')])) : null,
      network_scope: 'synthetic .test names mapped per-process to numeric loopback; no OS proxy/DNS/firewall change',
      implicit_bypass_control_verified: !infrastructureError,
      results, pac_fetches: pacHits.length,
      settings_observations: settingsObservations,
      corporate_direct_observed: unexpectedDirect,
      deadline_hit: deadlineHit,
      infrastructure_error: infrastructureError || null,
    };
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report, null, 2));
    fs.rmSync(directory, { recursive: true, force: true });
    process.exitCode = infrastructureError || deadlineHit ? 1 : unexpectedDirect.length ? 2 : 0;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

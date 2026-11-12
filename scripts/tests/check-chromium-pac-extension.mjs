#!/usr/bin/env node
// Synthetic API boundary tests; no browser, network, or user settings are used.
import assert from 'node:assert/strict';
import { createController, validatePacUrl } from '../../integrations/chromium-pac/controller.mjs';

let assertions = 0;
for (const value of ['http://127.0.0.1:1080/proxy.pac', 'http://[::1]:65535/proxy.pac']) {
  assert.equal(validatePacUrl(value), value); assertions++;
}
for (const value of ['', null, {}, 'https://127.0.0.1:1080/proxy.pac', 'http://localhost:1080/proxy.pac',
  'http://127.0.0.2:1080/proxy.pac', 'http://127.1:1080/proxy.pac', 'http://2130706433:1080/proxy.pac',
  'http://0x7f000001:1080/proxy.pac', 'http://127.0.0.1:0/proxy.pac', 'http://127.0.0.1:65536/proxy.pac',
  'http://127.0.0.1:01080/proxy.pac', 'http://127.0.0.1:1080/%70roxy.pac', 'http://127.0.0.1:1080/a/../proxy.pac',
  'http://127.0.0.1:1080/proxy.pac?x=1', 'http://127.0.0.1:1080/proxy.pac#x', 'http://user@127.0.0.1:1080/proxy.pac',
  'http://127.0.0.1:1080\\@remote.test/proxy.pac', 'http://[::ffff:127.0.0.1]:1080/proxy.pac']) {
  assert.throws(() => validatePacUrl(value), /invalid_url/); assertions++;
}
function mock(level = 'controllable_by_this_extension') {
  let setting = { levelOfControl: level, value: { mode: 'system' } };
  const calls = [];
  const api = { runtime: {}, proxy: { settings: {
    get(details, callback) { calls.push(['get', details]); callback(structuredClone(setting)); },
    set(details, callback) { calls.push(['set', details]); setting = { levelOfControl: 'controlled_by_this_extension', value: details.value }; callback(); },
    clear(details, callback) { calls.push(['clear', details]); setting = { levelOfControl: 'controllable_by_this_extension', value: { mode: 'system' } }; callback(); },
  } } };
  return { api, calls, controller: createController(api) };
}
const ordinary = mock();
assert.equal((await ordinary.controller.status()).enabled, false); assertions++;
assert.equal(ordinary.calls.some(([name]) => name !== 'get'), false); assertions++;
await ordinary.controller.enable('http://127.0.0.1:1080/proxy.pac');
assert.deepEqual(ordinary.calls.find(([name]) => name === 'set')[1], {
  scope: 'regular', value: { mode: 'pac_script', pacScript: { url: 'http://127.0.0.1:1080/proxy.pac', mandatory: true } },
}); assertions++;
assert.equal((await ordinary.controller.disable()).owned, false); assertions++;
assert.deepEqual(ordinary.calls.find(([name]) => name === 'clear')[1], { scope: 'regular' }); assertions++;

for (const level of ['not_controllable', 'controlled_by_other_extensions']) {
  const other = mock(level);
  await assert.rejects(other.controller.enable('http://127.0.0.1:1080/proxy.pac'), /not_controllable/); assertions++;
  await assert.rejects(other.controller.disable(), /not_owned/); assertions++;
  assert(other.calls.every(([name]) => name === 'get')); assertions++;
}
const invalid = mock();
await assert.rejects(invalid.controller.enable('http://remote.test:1080/proxy.pac'), /invalid_url/); assertions++;
assert.equal(invalid.calls.length, 0); assertions++;
await assert.rejects(createController({ runtime: {} }).status(), /api_unavailable/); assertions++;
const failed = mock();
failed.api.proxy.settings.set = (_, callback) => {
  failed.api.runtime.lastError = { message: 'synthetic sensitive diagnostic must not escape' };
  callback(); delete failed.api.runtime.lastError;
};
await assert.rejects(failed.controller.enable('http://127.0.0.1:1080/proxy.pac'), error => error.message === 'api_failed'); assertions++;
const preempted = mock();
preempted.api.proxy.settings.set = (_, callback) => callback();
await assert.rejects(preempted.controller.enable('http://127.0.0.1:1080/proxy.pac'), /not_effective/); assertions++;
assert.equal(preempted.calls.some(([name]) => name === 'clear'), false); assertions++;

const refreshing = mock();
const controller = createController(refreshing.api, { getRandomValues(bytes) { bytes.fill(0); return bytes; } });
await assert.rejects(controller.refresh(), /not_enabled/); assertions++;
assert(refreshing.calls.every(([name]) => name === 'get')); assertions++;
await controller.enable('http://127.0.0.1:1080/proxy.pac');
refreshing.calls.length = 0;
const refreshed = await controller.refresh();
assert.equal(refreshed.enabled, true); assertions++;
assert.equal(refreshed.url, 'http://127.0.0.1:1080/proxy.pac'); assertions++;
assert.deepEqual(refreshing.calls.map(([name]) => name), ['get', 'set', 'get']); assertions++;
assert.deepEqual(refreshing.calls[1][1], { scope: 'regular', value: { mode: 'pac_script', pacScript: { mandatory: true, url: 'http://127.0.0.1:1080/proxy.pac?gpv=' + '0'.repeat(32) } } }); assertions++;
refreshing.calls.length = 0;
await controller.refresh();
assert.equal(refreshing.calls[1][1].value.pacScript.url, 'http://127.0.0.1:1080/proxy.pac?gpv=01' + '0'.repeat(30)); assertions++;
assert.equal(refreshing.calls.some(([name]) => name === 'clear'), false); assertions++;
await controller.disable();
assert.equal((await controller.status()).enabled, false); assertions++;

for (const level of ['not_controllable', 'controlled_by_other_extensions', 'controllable_by_this_extension']) {
  const unavailable = mock(level);
  await assert.rejects(unavailable.controller.refresh(), /not_enabled/); assertions++;
  assert(unavailable.calls.every(([name]) => name === 'get')); assertions++;
}
for (const url of ['http://remote.test:1080/proxy.pac', 'http://127.0.0.1:1080/proxy.pac?other=1',
  'http://127.0.0.1:1080/proxy.pac?gpv=' + '0'.repeat(31),
  'http://127.0.0.1:1080/proxy.pac?gpv=' + 'F'.repeat(32),
  'http://127.0.0.1:1080/proxy.pac?gpv=' + '0'.repeat(32) + '&gpv=0']) {
  const malformed = mock();
  malformed.api.proxy.settings.get = (_, callback) => callback({ levelOfControl: 'controlled_by_this_extension', value: { mode: 'pac_script', pacScript: { url, mandatory: true } } });
  await assert.rejects(malformed.controller.refresh(), /not_enabled/); assertions++;
  assert.equal(malformed.calls.length, 0); assertions++;
}
const noRandom = mock();
await noRandom.controller.enable('http://127.0.0.1:1080/proxy.pac');
noRandom.calls.length = 0;
await assert.rejects(createController(noRandom.api, {}).refresh(), /api_failed/); assertions++;
assert(noRandom.calls.every(([name]) => name === 'get')); assertions++;
const overwrittenRefresh = mock();
await overwrittenRefresh.controller.enable('http://127.0.0.1:1080/proxy.pac');
overwrittenRefresh.api.proxy.settings.set = (_, callback) => callback();
await assert.rejects(overwrittenRefresh.controller.refresh(), /not_effective/); assertions++;
console.log(JSON.stringify({ audit: 'synthetic extension API boundaries (not browser policy integration)', assertions, passed: true }, null, 2));

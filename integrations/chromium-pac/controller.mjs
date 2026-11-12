// Browser proxy settings are the source of truth; no credentials or history are stored.
export function validatePacUrl(value) {
  if (typeof value !== 'string' || value.length > 100) throw new Error('invalid_url');
  const url = value.trim();
  const match = /^http:\/\/(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})\/proxy\.pac$/.exec(url);
  if (!match || Number(match[2]) > 65535) throw new Error('invalid_url');
  return url;
}

function configuredPacUrl(value) {
  if (typeof value !== 'string' || value.length > 140) throw new Error('invalid_url');
  const parts = value.split('?');
  if (parts.length > 2 || (parts.length === 2 && !/^gpv=[0-9a-f]{32}$/.test(parts[1]))) throw new Error('invalid_url');
  return { base: validatePacUrl(parts[0]), full: value };
}

export function createController(api, random = globalThis.crypto) {
  function call(method, parameters) {
    return new Promise((resolve, reject) => {
      if (!api.proxy?.settings?.[method]) return reject(new Error('api_unavailable'));
      try {
        api.proxy.settings[method](parameters, result => {
          // Read lastError within its callback lifetime, never expose its raw text.
          if (api.runtime.lastError) reject(new Error('api_failed'));
          else resolve(result);
        });
      } catch { reject(new Error('api_failed')); }
    });
  }
  const get = () => call('get', { incognito: false });
  function summarize(setting) {
    const owned = setting.levelOfControl === 'controlled_by_this_extension';
    let url = null;
    if (owned) {
      try { url = configuredPacUrl(setting.value?.pacScript?.url).base; } catch { /* static status only */ }
    }
    return {
      owned,
      controllable: ['controllable_by_this_extension', 'controlled_by_this_extension'].includes(setting.levelOfControl),
      enabled: owned && setting.value?.mode === 'pac_script' && setting.value?.pacScript?.mandatory === true && url !== null,
      url,
    };
  }
  return {
    async status() { return summarize(await get()); },
    async enable(input) {
      const url = validatePacUrl(input);
      const before = summarize(await get());
      if (!before.controllable) throw new Error('not_controllable');
      await call('set', { value: { mode: 'pac_script', pacScript: { url, mandatory: true } }, scope: 'regular' });
      const setting = await get();
      const after = summarize(setting);
      if (!after.enabled || setting.value.pacScript.url !== url) throw new Error('not_effective');
      return after;
    },
    async refresh() {
      const setting = await get();
      if (!summarize(setting).enabled) throw new Error('not_enabled');
      const current = configuredPacUrl(setting.value.pacScript.url);
      const bytes = new Uint8Array(16);
      try { random.getRandomValues(bytes); } catch { throw new Error('api_failed'); }
      const encode = () => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
      // The version is only a cache key, not a credential. Even an unlikely
      // collision with the current key must produce a different URL.
      if (current.full === current.base + '?gpv=' + encode()) bytes[0] ^= 1;
      const url = current.base + '?gpv=' + encode();
      await call('set', { value: { mode: 'pac_script', pacScript: { url, mandatory: true } }, scope: 'regular' });
      const updated = await get();
      const after = summarize(updated);
      if (!after.enabled || updated.value.pacScript.url !== url) throw new Error('not_effective');
      return after;
    },
    async disable() {
      // clear removes only this extension's setting, never writes a replacement
      // system/direct configuration over settings belonging to another controller.
      if (!summarize(await get()).owned) throw new Error('not_owned');
      await call('clear', { scope: 'regular' });
      const after = summarize(await get());
      if (after.owned) throw new Error('clear_failed');
      return after;
    },
  };
}

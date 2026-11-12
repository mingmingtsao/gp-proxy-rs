import { createController } from './controller.mjs';

const controller = createController(chrome);
let pending = Promise.resolve();
const knownErrors = new Set(['invalid_url', 'api_unavailable', 'api_failed', 'not_controllable', 'not_effective', 'not_owned', 'not_enabled', 'clear_failed']);

// No onInstalled/onStartup setting changes. Only this extension's own popup
// can request changes, and the popup sends them only after an explicit click.
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('popup.html')) return false;
  if (!message || !['status', 'enable', 'refresh', 'disable'].includes(message.action)) return false;
  const action = message.action;
  pending = pending.then(async () => {
    try {
      const state = action === 'enable' ? await controller.enable(message.url) : await controller[action]();
      respond({ ok: true, state });
    } catch (error) {
      respond({ ok: false, error: knownErrors.has(error.message) ? error.message : 'api_failed' });
    }
  }).catch(() => { /* A closed popup must not poison later explicit actions. */ });
  return true;
});

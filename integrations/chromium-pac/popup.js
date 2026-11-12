const status = document.querySelector('#status');
const input = document.querySelector('#pac-url');
const enable = document.querySelector('#enable');
const refresh = document.querySelector('#refresh');
const disable = document.querySelector('#disable');
const error = document.querySelector('#error');
const notice = document.querySelector('#notice');
const messages = {
  invalid_url: '请输入合法的本机 PAC 地址，包含端口和 /proxy.pac 路径。',
  api_unavailable: '此浏览器未提供代理设置权限。',
  api_failed: '浏览器未完成设置操作。请重新打开扩展检查当前状态。',
  not_controllable: '代理由浏览器策略或其他扩展控制，未作更改。',
  not_effective: '严格 PAC 未成为当前有效设置，请检查浏览器策略或其他扩展。',
  not_owned: '当前代理不由本扩展控制，未作更改。',
  not_enabled: '请先启用本扩展的严格 PAC，当前未作更改。',
  clear_failed: '未能确认停用，请重新打开扩展检查当前状态。',
};
function render(state) {
  status.textContent = state.enabled ? '严格 PAC 已启用' : state.owned ? '本扩展设置异常，请检查或停用' : state.controllable ? '未启用，代理设置未更改' : '代理由策略或其他扩展控制';
  status.dataset.enabled = String(state.enabled);
  if (state.url) input.value = state.url;
  enable.disabled = !state.controllable;
  disable.disabled = !state.owned;
  refresh.disabled = !state.enabled;
}
async function request(action) {
  enable.disabled = refresh.disabled = disable.disabled = true;
  error.textContent = '';
  notice.textContent = '';
  try {
    const result = await chrome.runtime.sendMessage({ action, ...(action === 'enable' ? { url: input.value } : {}) });
    if (result?.ok) {
      render(result.state);
      if (action === 'refresh') notice.textContent = '已请求刷新，不代表 VPN 或规则验证完成。请关闭旧连接，并验证目标规则。';
    }
    else {
      error.textContent = messages[result?.error] || messages.api_failed;
      if (action !== 'status') {
        const current = await chrome.runtime.sendMessage({ action: 'status' });
        if (current?.ok) render(current.state);
      }
    }
  } catch { error.textContent = messages.api_failed; }
}
enable.addEventListener('click', () => request('enable'));
refresh.addEventListener('click', () => request('refresh'));
disable.addEventListener('click', () => request('disable'));
request('status');

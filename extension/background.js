// The unlocked session (server token + vault keys) lives only in chrome.storage.session (memory).
// It is dropped when the computer is locked or idle for 15 minutes.
chrome.idle.setDetectionInterval(900);
chrome.idle.onStateChanged.addListener((s) => { if (s !== 'active') chrome.storage.session.remove('sess'); });

// Clipboard clearing must outlive the popup (it closes as soon as you click the page), so the popup asks the
// service worker, which sets a 30 s alarm and then empties the clipboard through an offscreen document.
chrome.runtime.onMessage.addListener((msg) => { if (msg?.type === 'clear-clipboard-later') chrome.alarms.create('clear-clipboard', { delayInMinutes: 0.5 }); });
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name !== 'clear-clipboard') return;
  if (!(await chrome.offscreen.hasDocument())) await chrome.offscreen.createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Clear a copied password from the clipboard after 30 seconds' });
  await chrome.runtime.sendMessage({ type: 'clear-clipboard-now' });
  setTimeout(() => chrome.offscreen.closeDocument().catch(() => {}), 1000);
});

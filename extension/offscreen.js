// Empties the clipboard (offscreen documents cannot use navigator.clipboard, but can use execCommand('copy')).
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== 'clear-clipboard-now') return;
  const t = document.getElementById('t');
  t.value = ' '; t.select(); document.execCommand('copy');   // a single space: some systems ignore an empty copy
});

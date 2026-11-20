// The unlocked session (server token + vault keys) lives only in chrome.storage.session (memory).
// It is dropped when the computer is locked or idle for 15 minutes.
chrome.idle.setDetectionInterval(900);
chrome.idle.onStateChanged.addListener((s) => { if (s !== 'active') chrome.storage.session.remove('sess'); });

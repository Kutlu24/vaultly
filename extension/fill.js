// Runs inside the page (injected with chrome.scripting.executeScript). Must stay self-contained.
export function fillForm(username, password) {
  const visible = (e) => { const r = e.getBoundingClientRect(), s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !e.disabled && !e.readOnly; };
  const set = (e, v) => {
    const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, v); // works with React/Vue controlled inputs
    for (const t of ['input', 'change']) e.dispatchEvent(new Event(t, { bubbles: true }));
    e.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll('input')].filter(visible);
  const pw = inputs.filter((i) => i.type === 'password');
  const texty = (i) => ['text', 'email', 'tel', ''].includes(i.type) && !/search|captcha|otp|code/i.test(i.name + i.id + i.autocomplete);
  let filled = 0;
  if (pw.length) {
    const target = pw[0];
    const before = inputs.slice(0, inputs.indexOf(target)).reverse().find(texty);
    const user = document.querySelector('input[autocomplete="username"]') || before;
    if (user && username) { set(user, username); filled++; }
    if (password) { set(target, password); filled++; }
  } else {
    const u = document.querySelector('input[autocomplete="username"]') || inputs.find((i) => i.type === 'email') || inputs.find(texty);
    if (u && username) { set(u, username); filled++; }
  }
  return filled;
}

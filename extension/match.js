// Which stored logins may be offered for the current page. Deliberately strict: exact host, no subdomain guessing
// (without the Public Suffix List, "github.io" would match every user's site), and never https -> http.
export function parseUrl(u) {
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : 'https://' + u); } catch { return null; }
}
export const normHost = (h) => h.toLowerCase().replace(/^www\./, '');
const effPort = (u) => u.port || (u.protocol === 'https:' ? '443' : '80');
export function urlMatches(pageUrl, storedUrl) {
  const p = parseUrl(pageUrl), s = parseUrl(storedUrl);
  if (!p || !s || !['http:', 'https:'].includes(p.protocol) || !['http:', 'https:'].includes(s.protocol)) return false;
  if (normHost(p.hostname) !== normHost(s.hostname)) return false;
  if (s.protocol === p.protocol) return effPort(s) === effPort(p);                        // same scheme: ports must be equal (defaults filled in)
  return s.protocol === 'http:' && p.protocol === 'https:' && effPort(s) === '80' && effPort(p) === '443'; // only a plain http -> https upgrade on default ports
}

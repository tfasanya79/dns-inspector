const express = require('express');
const rateLimit = require('express-rate-limit');
const dns = require('dns').promises;
const dnsLookup = require('dns').lookup;
const https = require('https');
const path = require('path');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 8104;

app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, '..', 'public')));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait a minute and try again.' },
});
app.use('/api/', limiter);

const DNS_TIMEOUT_MS = 4000;
const HTTP_TIMEOUT_MS = 5000;
const MAX_REDIRECTS = 3;

const COMMON_DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'dkim',
  'mail', 'smtp', 's1', 's2', 'mandrill', 'sendgrid',
];

const SECURITY_HEADERS = [
  { key: 'strict-transport-security', label: 'Strict-Transport-Security', weight: 20,
    desc: 'Forces browsers to only ever connect over HTTPS, preventing protocol downgrade attacks.',
    good: 'Good. An attacker on the same network cannot downgrade this connection to unencrypted HTTP.',
    risk: 'Someone on the same network, for example public WiFi, could potentially force a visitor onto an unencrypted HTTP connection and intercept traffic.' },
  { key: 'content-security-policy', label: 'Content-Security-Policy', weight: 25,
    desc: 'Restricts which scripts, styles, and resources can load, the single strongest defense against XSS.',
    good: 'Good. Even if an attacker injects a malicious script into the page, the browser is told not to run it.',
    risk: 'If an attacker finds a way to inject a script into this page, for example through a comment field or a vulnerable plugin, the browser has no extra instructions telling it to block that script from running.' },
  { key: 'x-frame-options', label: 'X-Frame-Options', weight: 15,
    desc: 'Prevents the site from being embedded in a hidden iframe, a common clickjacking technique.',
    good: 'Good. This page cannot be loaded inside a hidden frame on another site.',
    risk: 'This page could be loaded inside an invisible frame on a malicious site, tricking visitors into clicking something they did not intend to, known as clickjacking.' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 10,
    desc: 'Stops browsers from guessing content types in a way that can be abused to run untrusted files as scripts.',
    good: 'Good. Browsers are told to trust the declared file type instead of guessing it.',
    risk: 'A browser could be tricked into guessing that an uploaded file, for example an image, is actually a script, and run it.' },
  { key: 'referrer-policy', label: 'Referrer-Policy', weight: 10,
    desc: 'Controls how much of the current URL is leaked to other sites when a user clicks a link.',
    good: 'Good. The site limits how much of its URL is shared with other sites when a visitor clicks a link.',
    risk: 'The full page URL, which can include search terms or other sensitive details in the address, may be sent along to whatever site a visitor clicks through to.' },
  { key: 'permissions-policy', label: 'Permissions-Policy', weight: 10,
    desc: 'Restricts access to sensitive browser features like camera, microphone, and geolocation.',
    good: 'Good. Access to sensitive features like camera, microphone, and location is explicitly locked down.',
    risk: 'Embedded content or third party scripts on this page are not explicitly blocked from requesting access to a visitor camera, microphone, or location.' },
  { key: 'x-xss-protection', label: 'X-XSS-Protection', weight: 5,
    desc: 'A legacy header for older browsers, largely superseded by Content-Security-Policy.',
    good: 'Present. This only matters on old browsers, modern ones rely on Content-Security-Policy instead.',
    risk: 'Minor. This is a legacy header for old browsers and has little effect on modern ones, Content-Security-Policy matters far more.' },
];

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true;
    if (lower.startsWith('fe80:')) return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('::ffff:')) return isPrivateIp(lower.replace('::ffff:', ''));
    return false;
  }
  return true;
}

function safeLookup(hostname, options, callback) {
  dnsLookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const addresses = Array.isArray(address) ? address : [{ address, family }];
    for (const a of addresses) {
      if (isPrivateIp(a.address || address)) {
        return callback(new Error('Refusing to connect to a private or reserved address'));
      }
    }
    callback(null, address, family);
  });
}

function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  const re = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$/;
  return re.test(domain);
}

function normalizeDomain(input) {
  let d = (input || '').trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.split('/')[0];
  d = d.split(':')[0];
  return d;
}

async function checkSpf(domain) {
  const records = await withTimeout(dns.resolveTxt(domain).catch(() => []), DNS_TIMEOUT_MS, []);
  const flat = records.map(r => r.join(''));
  const spf = flat.find(r => r.toLowerCase().startsWith('v=spf1'));
  if (!spf) return { found: false, record: null };
  const hardFail = spf.includes('-all');
  const softFail = spf.includes('~all');
  return { found: true, record: spf, strict: hardFail, soft: softFail && !hardFail };
}

async function checkDmarc(domain) {
  const records = await withTimeout(dns.resolveTxt('_dmarc.' + domain).catch(() => []), DNS_TIMEOUT_MS, []);
  const flat = records.map(r => r.join(''));
  const dmarc = flat.find(r => r.toLowerCase().startsWith('v=dmarc1'));
  if (!dmarc) return { found: false, record: null };
  const policyMatch = dmarc.match(/p=(\w+)/i);
  const policy = policyMatch ? policyMatch[1].toLowerCase() : 'none';
  return { found: true, record: dmarc, policy };
}

async function checkDkim(domain) {
  for (const selector of COMMON_DKIM_SELECTORS) {
    const records = await withTimeout(
      dns.resolveTxt(selector + '._domainkey.' + domain).catch(() => []),
      DNS_TIMEOUT_MS,
      []
    );
    const flat = records.map(r => r.join(''));
    const dkim = flat.find(r => r.toLowerCase().includes('v=dkim1') || r.toLowerCase().includes('p='));
    if (dkim) return { found: true, selector, record: dkim };
  }
  return { found: false, selector: null, checkedSelectors: COMMON_DKIM_SELECTORS };
}

async function checkMx(domain) {
  const records = await withTimeout(dns.resolveMx(domain).catch(() => []), DNS_TIMEOUT_MS, []);
  return records.sort((a, b) => a.priority - b.priority);
}

function fetchHeaders(domain, redirectsLeft) {
  return new Promise((resolve) => {
    const options = {
      hostname: domain,
      port: 443,
      path: '/',
      method: 'HEAD',
      timeout: HTTP_TIMEOUT_MS,
      lookup: safeLookup,
      headers: { 'User-Agent': 'passcheck-dns-inspector/1.0' },
    };

    const req = https.request(options, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectsLeft > 0) {
        req.destroy();
        try {
          const nextUrl = new URL(res.headers.location, 'https://' + domain);
          resolve(fetchHeaders(nextUrl.hostname, redirectsLeft - 1));
        } catch {
          resolve({ error: 'Redirect target could not be parsed', headers: {}, statusCode: res.statusCode });
        }
        return;
      }
      resolve({ headers: res.headers, statusCode: res.statusCode, finalHost: domain });
      req.destroy();
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'Request timed out', headers: {} });
    });
    req.on('error', (err) => {
      resolve({ error: err.message, headers: {} });
    });
    req.end();
  });
}

function gradeFromHeaders(headers) {
  let score = 0;
  let max = 0;
  const details = SECURITY_HEADERS.map((h) => {
    max += h.weight;
    const present = Boolean(headers[h.key]);
    if (present) score += h.weight;
    return { ...h, present, value: headers[h.key] || null, meaning: present ? h.good : h.risk };
  });
  const pct = max === 0 ? 0 : Math.round((score / max) * 100);
  let letter;
  let summary;
  if (pct >= 90) { letter = 'A'; summary = 'Strong. This site has nearly all the recommended browser security headers in place.'; }
  else if (pct >= 75) { letter = 'B'; summary = 'Good. Most of the recommended browser security headers are in place, with a couple of minor gaps.'; }
  else if (pct >= 55) { letter = 'C'; summary = 'Fair. The basics are missing in a few places. These are extra layers of defense, not a sign the site is unsafe to use.'; }
  else if (pct >= 35) { letter = 'D'; summary = 'Weak. Several recommended headers are missing, leaving fewer safety nets against common browser based attacks.'; }
  else { letter = 'F'; summary = 'Poor. Most recommended headers are missing. This does not mean the site has been breached, but it is not following current best practices.'; }
  return { letter, pct, summary, details };
}

app.get('/api/check', async (req, res) => {
  const domain = normalizeDomain(req.query.domain);

  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: 'Enter a valid domain name, for example example.com' });
  }

  try {
    const resolved = await withTimeout(dns.lookup(domain).catch(() => null), DNS_TIMEOUT_MS, null);
    if (resolved && isPrivateIp(resolved.address)) {
      return res.status(400).json({ error: 'This domain resolves to a private or reserved address and cannot be checked.' });
    }
  } catch {
    return res.status(400).json({ error: 'Could not resolve this domain.' });
  }

  const [spf, dmarc, dkim, mx, headerResult] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
    checkDkim(domain),
    checkMx(domain),
    fetchHeaders(domain, MAX_REDIRECTS),
  ]);

  const grade = gradeFromHeaders(headerResult.headers || {});

  res.json({
    domain,
    spf,
    dmarc,
    dkim,
    mx,
    headers: headerResult,
    grade,
  });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log('dns-inspector listening on 127.0.0.1:' + PORT);
});

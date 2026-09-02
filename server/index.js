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
    desc: 'Forces browsers to only ever connect over HTTPS, preventing protocol downgrade attacks.' },
  { key: 'content-security-policy', label: 'Content-Security-Policy', weight: 25,
    desc: 'Restricts which scripts, styles, and resources can load, the single strongest defense against XSS.' },
  { key: 'x-frame-options', label: 'X-Frame-Options', weight: 15,
    desc: 'Prevents the site from being embedded in a hidden iframe, a common clickjacking technique.' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 10,
    desc: 'Stops browsers from guessing content types in a way that can be abused to run untrusted files as scripts.' },
  { key: 'referrer-policy', label: 'Referrer-Policy', weight: 10,
    desc: 'Controls how much of the current URL is leaked to other sites when a user clicks a link.' },
  { key: 'permissions-policy', label: 'Permissions-Policy', weight: 10,
    desc: 'Restricts access to sensitive browser features like camera, microphone, and geolocation.' },
  { key: 'x-xss-protection', label: 'X-XSS-Protection', weight: 5,
    desc: 'A legacy header for older browsers, largely superseded by Content-Security-Policy.' },
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
    return { ...h, present, value: headers[h.key] || null };
  });
  const pct = max === 0 ? 0 : Math.round((score / max) * 100);
  let letter;
  if (pct >= 90) letter = 'A';
  else if (pct >= 75) letter = 'B';
  else if (pct >= 55) letter = 'C';
  else if (pct >= 35) letter = 'D';
  else letter = 'F';
  return { letter, pct, details };
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

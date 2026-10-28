# DNS Inspector

A web tool that checks a domain's email authentication setup and browser security headers, then explains the results in plain English.

Live at: https://timfas.com/inspect/

## What it checks

**Email authentication**
- SPF record, so you can see which servers are authorized to send mail for the domain
- DKIM, checked against a list of common selectors, since DKIM selectors are not publicly discoverable from DNS alone
- DMARC record and policy, the rule that tells receiving mail servers what to do with messages that fail SPF or DKIM
- MX records, the mail servers that actually receive mail for the domain

**Security headers**
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection

Each header is explained in plain language and the domain gets an overall letter grade from A to F based on a weighted scoring system.

## Why this matters

A missing or misconfigured SPF, DKIM, or DMARC record makes it easier for attackers to spoof email from a domain, and can also cause legitimate email to land in spam. Missing security headers leave a site more exposed to clickjacking, content sniffing attacks, and cross site scripting. This tool gives domain owners, developers, and IT admins a fast way to check their setup and catch regressions after a deploy or a DNS change.

## How it works

The frontend is a single static page. It sends the domain to a small Node and Express backend, which performs the DNS lookups and fetches the site's response headers, then returns everything as JSON for the page to render.

A backend is required here, unlike some of the other tools in this portfolio, because browsers block cross origin DNS lookups and many cross origin header reads, so the checks have to run server side.

### Safety measures in the backend

- Domain input is validated and normalized before use
- Outbound HTTP requests resolve through a custom DNS lookup that blocks private, loopback, and link local IP ranges, so the tool cannot be used to probe internal network services
- Redirects are followed up to a limit of three hops, and each hop is revalidated
- Requests are capped with timeouts on both DNS and HTTP calls
- Rate limiting caps requests per IP address

## Tech stack

- Node.js and Express on the backend
- Vanilla HTML, CSS, and JavaScript on the frontend, no build step and no frameworks
- Served behind Caddy as a reverse proxy

## Running it yourself

```
npm install
npm start
```

The server listens on port 8104 by default and serves both the API and the static frontend.

## Part of a portfolio

This is one of several small, single purpose web tools built for a public portfolio. See the full list at https://timfas.com/
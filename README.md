# 🏹 Domain Hunter

**HugeDomains Scraper + WHOIS Lookup** — Web app with REST API, deployable on Vercel.

Scrapes domain listings from HugeDomains.com and performs WHOIS date lookups to find domains with specific registration spans (e.g., 10-year registrations).

![Domain Hunter](https://img.shields.io/badge/Deploy-Vercel-black?style=flat-square&logo=vercel)

---

## Features

- **Search** HugeDomains by keyword, price range, and result count
- **WHOIS lookup** for all results — shows created/expires dates, registration years, registrar
- **10-Year filter** — highlight domains with exactly 10-year registration spans
- **Export CSV** — download filtered or full results
- **Raw WHOIS viewer** — inspect full WHOIS response for any domain
- Right-click context menu: Google search, copy, individual WHOIS
- Dark theme, responsive design

## REST API

| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/api/scrape` | GET | `keyword`, `price_max`, `max_rows` | Scrape HugeDomains listings |
| `/api/whois` | GET | `domain` | WHOIS lookup for a single domain |

### Example

```bash
# Search for domains
curl "https://your-app.vercel.app/api/scrape?keyword=sport&price_max=495&max_rows=50"

# WHOIS lookup
curl "https://your-app.vercel.app/api/whois?domain=example.com"
```

### Response: `/api/scrape`
```json
{
  "domains": [
    { "domain": "sportzone.com", "price": "2495" }
  ],
  "count": 42
}
```

### Response: `/api/whois`
```json
{
  "domain": "example.com",
  "created": "1995-08-14",
  "expires": "2025-08-13",
  "years": 30.0,
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "raw": "..."
}
```

## Deploy to Vercel

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USER/domain-hunter.git
git push -u origin main
```

### 2. Deploy on Vercel

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New Project"**
3. Import your `domain-hunter` repository
4. Framework preset: **Other**
5. Click **Deploy**

That's it — Vercel auto-detects the Python serverless functions and static frontend.

### Alternative: Vercel CLI

```bash
npm i -g vercel
vercel
```

## Project Structure

```
domain-hunter/
├── api/
│   ├── scrape.py       # Serverless: HugeDomains scraper
│   └── whois.py        # Serverless: raw socket WHOIS client
├── public/
│   └── index.html      # Frontend SPA
├── vercel.json          # Vercel routing & build config
├── requirements.txt     # Python dependencies
└── README.md
```

## Local Development

```bash
# Install Vercel CLI
npm i -g vercel

# Run locally (emulates serverless functions)
vercel dev
```

Opens at `http://localhost:3000`.

## Notes

- **WHOIS rate limiting**: Some WHOIS servers rate-limit queries. The app processes domains sequentially with natural delays between requests.
- **Vercel timeout**: Serverless functions have a 60s timeout (Pro plan). Individual WHOIS lookups typically complete in 2-5 seconds.
- **HugeDomains scraping**: Results depend on HugeDomains' current page structure. Multiple parsing strategies are used as fallbacks.

## License

MIT

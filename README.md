# ⚡ Domain Hunter

HugeDomains scraper + WHOIS lookup — deployed as a web app on Vercel.

## Architecture

```
domain-hunter/
├── api/
│   ├── scrape.py        # POST /api/scrape — scrape HugeDomains
│   └── whois.py         # POST /api/whois  — WHOIS lookup
├── lib/
│   ├── __init__.py
│   └── whois_lib.py     # Shared WHOIS client (raw TCP sockets)
├── public/
│   └── index.html       # Frontend SPA
├── requirements.txt     # Python deps (requests, beautifulsoup4)
├── vercel.json          # Vercel routing config
└── README.md
```

## REST API

### `POST /api/scrape`

Scrape domain listings from HugeDomains.

**Request:**
```json
{
  "keyword": "sport",
  "price_max": "495",
  "max_rows": 100
}
```

**Response:**
```json
{
  "domains": [
    { "domain": "sportzone.com", "price": "$2,495" },
    { "domain": "sportify.com", "price": "$3,995" }
  ],
  "count": 2
}
```

### `POST /api/whois`

WHOIS lookup for one or multiple domains (max 20 per request).

**Request:**
```json
{
  "domains": ["sportzone.com", "sportify.com"]
}
```

**Response:**
```json
{
  "results": {
    "sportzone.com": {
      "created": "2014-03-15",
      "expires": "2024-03-15",
      "registrar": "NameSilo, LLC",
      "error": null
    }
  }
}
```

## Deploy to Vercel

### 1. Push to GitHub

```bash
cd domain-hunter
git init
git add .
git commit -m "Initial commit"
gh repo create domain-hunter --public --push
```

### 2. Deploy

```bash
# Option A: Vercel CLI
npm i -g vercel
vercel

# Option B: Connect GitHub repo at vercel.com/new
```

That's it. Vercel auto-detects the Python serverless functions and static frontend.

## Local Development

```bash
# Install Vercel CLI
npm i -g vercel

# Run locally
vercel dev
```

Opens at `http://localhost:3000`.

## Notes

- **WHOIS** uses raw TCP sockets (port 43) — no external `python-whois` dependency needed
- **Rate limiting:** Vercel hobby plan has a 10-second function timeout; WHOIS batches are capped at 20 domains per request
- **Proxy support** from the original desktop app was removed since Vercel serverless functions run from cloud IPs

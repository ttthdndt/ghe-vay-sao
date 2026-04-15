# 🏹 Domain Hunter

HugeDomains scraper + WHOIS lookup — Flask web app deployed on Vercel.

## Features

- **Search** — Scrape domain listings from HugeDomains.com by keyword
- **WHOIS Lookup** — Check creation/expiration dates via raw socket WHOIS queries
- **10-Year Filter** — Highlight domains with exactly 10-year registration spans
- **Export CSV** — Download filtered results
- **Right-click** — Google search, single WHOIS, view raw WHOIS, copy domain

## Deploy to Vercel

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/domain-hunter.git
git push -u origin main
```

### 2. Deploy on Vercel

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import your GitHub repo
3. Framework preset: **Other**
4. Click **Deploy**

That's it — Vercel auto-detects the Python serverless function and static files.

### Local Development

```bash
pip install -r requirements.txt
python api/index.py
# Open http://localhost:5000
```

## Project Structure

```
domain-hunter/
├── api/
│   └── index.py          # Flask API (serverless on Vercel)
├── public/
│   └── index.html         # Frontend SPA
├── vercel.json            # Vercel routing config
├── requirements.txt       # Python deps
└── README.md
```

## Note on WHOIS

Raw socket WHOIS queries (port 43) may be blocked on some serverless platforms.
If WHOIS fails on Vercel, the scraping still works — you can run WHOIS locally
or use a WHOIS API provider as a fallback.

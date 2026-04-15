# 🏹 Domain Hunter

HugeDomains scraper + WHOIS lookup web app. Built with Flask, deployable to Vercel.

## Features

- Scrape domain listings from HugeDomains.com by keyword
- WHOIS lookup (raw socket, no external library) — checks created/expires dates
- Filter for **10-year registrations** (strong SEO signal)
- Sort by any column
- Export visible results to CSV
- View raw WHOIS response per domain

---

## Local Development

```bash
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

---

## Deploy to Vercel via GitHub

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/domain-hunter.git
git push -u origin main
```

### 2. Connect to Vercel

1. Go to [vercel.com](https://vercel.com) → **Add New Project**
2. Import your GitHub repo
3. Framework: **Other** (Vercel auto-detects Python via `vercel.json`)
4. Click **Deploy** — done!

Vercel will pick up `vercel.json` automatically and route all requests to `app.py`.

### Notes on Vercel

- Hobby plan: 10s function timeout per request
- WHOIS lookups are done one at a time from the browser to stay within limits
- Raw socket WHOIS works fine on Vercel's serverless infrastructure
- The scraping endpoint may occasionally time out on very large `max_rows` values — keep it under 100 for safety

---

## Project Structure

```
domain-hunter/
├── app.py              # Flask app + WHOIS client + scraper
├── templates/
│   └── index.html      # Single-page frontend
├── requirements.txt
├── vercel.json         # Vercel routing config
└── .gitignore
```

---

## API Endpoints

### `POST /api/search`
```json
{ "keyword": "sport", "price_max": "495", "max_rows": 100 }
```
Returns: `{ "domains": [...], "count": N }`

### `POST /api/whois`
```json
{ "domain": "example.com" }
```
Returns: `{ "domain": "...", "created": "YYYY-MM-DD", "expires": "YYYY-MM-DD", "years": "10.0", "registrar": "...", "raw": "..." }`

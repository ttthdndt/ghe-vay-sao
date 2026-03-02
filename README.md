# HugeDomains Sport Scraper

A FastAPI web app that scrapes domain listings from HugeDomains and enriches them with WHOIS data (Created / Expires dates) from who.is.

## Features
- Scrape domains with `sport` keyword (price $15–$1000, length 8–10 chars)
- WHOIS lookup: Created Date & Expiry Date per domain
- Live search & price filter
- Sortable table columns
- Export filtered results as CSV
- Trigger fresh scrape from the UI

## Project Structure
```
hugedomains-app/
├── api/
│   └── index.py       # FastAPI app (Vercel entry point)
├── scraper.py          # Scraper + WHOIS logic
├── index.html          # Frontend UI
├── requirements.txt
├── vercel.json
└── .gitignore
```

## Local Development

```bash
pip install -r requirements.txt
uvicorn api.index:app --reload
# Open http://localhost:8000
```

## Deploy to GitHub + Vercel

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/hugedomains-scraper.git
git push -u origin main
```

### 2. Deploy to Vercel
```bash
npm i -g vercel   # install Vercel CLI (one-time)
vercel            # follow prompts — framework: Other, root: ./
```

Or connect via Vercel dashboard:
1. Go to https://vercel.com/new
2. Import your GitHub repo
3. Framework Preset → **Other**
4. Click **Deploy**

> ⚠️ **Note**: Vercel serverless functions have a max execution time of 10s (hobby) / 60s (pro).
> The scrape + WHOIS for 200+ domains takes several minutes.
> For production use, consider adding a database (e.g. Vercel Postgres or Supabase) to cache results,
> or run the scraper as a scheduled cron job.

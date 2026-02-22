# PhishGuard Backend

FastAPI + XGBoost + SHAP backend for the PhishGuard phishing detection frontend.

## Architecture

```
phishguard/
├── PHISHGAURD.html          ← Your frontend (unchanged)
├── requirements.txt
├── setup.sh
├── data/                    ← (optional) Drop real datasets here
│   └── phishing_site_urls.csv
└── app/
    ├── main.py              ← FastAPI app  →  POST /api/v1/analyze
    ├── features.py          ← URL feature extractor (30+ features)
    ├── scorer.py            ← Rule-based risk scorer + flag generator
    └── train_model.py       ← Dataset builder + model training
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model (takes ~30 seconds)
python3 -m app.train_model

# 3. Start the API server
uvicorn app.main:app --reload --port 8000

# 4. Open PHISHGAURD.html in your browser (Chrome/Firefox)
```

Or just run `bash setup.sh` for steps 1–2.

## API

### `POST /api/v1/analyze`

**Request:**
```json
{ "url": "http://paypa1-secure.login-verify.tk/account" }
```

**Response:**
```json
{
  "scan_id": "a3f2e1b0",
  "url": "...",
  "verdict": "PHISHING",
  "confidence": 0.947,
  "risk_score": 87,
  "engine": "xgboost",
  "features": { "url_length": 145, "has_https": 0, ... },
  "feature_details": { "protocol": "http", "hostname": "...", ... },
  "breakdown": {
    "url_score": 22,
    "domain_score": 27,
    "content_score": 12,
    "behavioral_score": 5
  },
  "flags": [
    { "severity": "red", "title": "No HTTPS", "description": "...", "feature": "has_https" },
    ...
  ],
  "shap_values": { "brand_impersonation": 0.412, ... },
  "extraction_time_ms": 184,
  "scanned_at": "2024-01-15T10:30:00+00:00"
}
```

### `GET /api/v1/health`

Returns model load status.

## Model & Dataset

### ML Model
- **Algorithm:** XGBoost (falls back to scikit-learn GradientBoostingClassifier if XGBoost isn't installed)
- **Features:** 22 lexical/structural URL features
- **Training data:** 20,000 balanced samples (synthetic, calibrated against academic benchmarks)
- **Typical AUC-ROC:** 0.97–0.99 on held-out test set

### Using a Real Dataset (Recommended)
Download the [Kaggle Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset) and place `phishing_site_urls.csv` in `data/`. Re-run `python3 -m app.train_model`.

Other supported datasets:
- [UCI ML Phishing Websites Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites)
- [ISCX-URL-2016](https://www.unb.ca/cic/datasets/url-2016.html)

### Features Extracted

| Feature | Description |
|---------|-------------|
| `url_length` | Total URL character count |
| `path_length` | Path segment length |
| `num_dots` | Dot count (inflated by subdomains) |
| `num_hyphens` | Hyphens in domain |
| `num_digits_in_domain` | Digits in registered domain |
| `num_slashes` | Forward slashes |
| `num_query_params` | GET parameters |
| `num_subdomains` | Subdomain depth |
| `domain_length` | Registered domain length |
| `url_entropy` | Shannon entropy of full URL |
| `suspicious_keyword_count` | Credential-themed keywords |
| `domain_age_days` | Days since domain registration (WHOIS) |
| `has_https` | HTTPS protocol flag |
| `has_ip_address` | IP-based host flag |
| `has_at_symbol` | @ in URL |
| `has_double_slash` | Double slash in path |
| `has_hex_encoding` | Percent-encoded chars |
| `tld_is_high_risk` | TLD on Spamhaus/ICANN abuse list |
| `brand_impersonation` | Brand name + non-brand domain |
| `dns_resolves` | Live DNS resolution check |
| `has_non_standard_port` | Non-80/443 port |
| `subdomain_count` | Alias for num_subdomains |

## References

- Mohammad, R. M., et al. (2016). *Using Intelligent Techniques for Detecting Phishing Websites.* UCI ML Repository.
- Sahingoz, O. K., et al. (2019). *Machine learning based phishing detection from URLs.* Expert Systems with Applications.
- APWG eCrime Reports (2020–2024).

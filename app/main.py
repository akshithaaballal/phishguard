"""
PhishGuard — FastAPI Backend
==============================
Endpoint: POST /api/v1/analyze
Response shape matches what PHISHGAURD.html renderResults() expects.

Start with:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

import json
import time
import uuid
import pathlib
from datetime import datetime, timezone
from typing import Optional, Any

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from app.features import extract_features, FEATURE_COLUMNS
from app.scorer import compute_risk_breakdown

# ─── Load model & scaler ──────────────────────────────────────────────────────
MODEL_DIR = pathlib.Path(__file__).parent / "model"
MODEL_PATH = MODEL_DIR / "phishguard_model.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
META_PATH = MODEL_DIR / "meta.json"

_model = None
_scaler = None
_engine_name = "rule-based"

def _load_model():
    global _model, _scaler, _engine_name
    if MODEL_PATH.exists() and SCALER_PATH.exists():
        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
            _scaler = joblib.load(SCALER_PATH)
            if META_PATH.exists():
                meta = json.loads(META_PATH.read_text())
                _engine_name = meta.get("engine", "ml-model")
            else:
                _engine_name = "ml-model"
            print(f"✅ Loaded ML model ({_engine_name})")
        except Exception as e:
            print(f"⚠️  Could not load ML model: {e}. Falling back to rule-based scoring.")
    else:
        print("⚠️  No trained model found. Run: python3 -m app.train_model")
        print("     Falling back to rule-based scoring.")

_load_model()

# ─── FastAPI app ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="AI-powered phishing URL detection — FastAPI + XGBoost + SHAP",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Allow the HTML frontend from any origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request / Response schemas ───────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str
    include_content: Optional[bool] = True

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v


# ─── Main analysis endpoint ───────────────────────────────────────────────────
@app.post("/api/v1/analyze")
async def analyze_url(req: AnalyzeRequest) -> dict[str, Any]:
    t0 = time.perf_counter()
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # 1. Feature extraction
    try:
        features, meta = extract_features(url)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Feature extraction failed: {e}")

    # 2. Rule-based risk breakdown
    breakdown_result = compute_risk_breakdown(features, meta)
    rule_score = breakdown_result["total"]          # 0–100

    # 3. ML model inference (if available)
    ml_prob = None
    shap_values: dict[str, float] = {}

    if _model is not None and _scaler is not None:
        try:
            feat_vec = np.array([[features[col] for col in FEATURE_COLUMNS]], dtype=float)
            feat_scaled = _scaler.transform(feat_vec)
            ml_prob = float(_model.predict_proba(feat_scaled)[0, 1])

            # SHAP explanations
            try:
                import shap
                explainer = shap.TreeExplainer(_model)
                shap_raw = explainer.shap_values(feat_scaled)
                # For binary classifiers shap_values may be list[array] or array
                if isinstance(shap_raw, list):
                    sv = shap_raw[1][0]  # class 1 (phishing)
                else:
                    sv = shap_raw[0]
                shap_values = {
                    FEATURE_COLUMNS[i]: round(float(sv[i]), 4)
                    for i in range(len(FEATURE_COLUMNS))
                }
                # Sort by absolute value, keep top 8
                shap_values = dict(
                    sorted(shap_values.items(), key=lambda kv: abs(kv[1]), reverse=True)[:8]
                )
            except Exception:
                pass  # SHAP optional

        except Exception as e:
            print(f"ML inference error: {e}")

    # 4. Combine scores
    if ml_prob is not None:
        risk_score = round(ml_prob * 60 + rule_score * 0.4)
        confidence = ml_prob if ml_prob > 0.5 else (1 - ml_prob)
        verdict = "PHISHING" if ml_prob >= 0.5 else "LEGITIMATE"
        engine = _engine_name

       # ── Rule-based override (safety net) ──────────────────────────
        danger_flags = sum(
            1 for f in breakdown_result["flags"] if f.get("severity") == "red"
        )
        if danger_flags >= 3 and verdict == "LEGITIMATE":
            verdict = "PHISHING"
            confidence = max(confidence, 0.85)
            risk_score = max(risk_score, 75)
            engine = _engine_name + "+override"
    else:
        # Pure rule-based
        risk_score = rule_score
        confidence = min(0.5 + rule_score / 200.0, 0.97)
        verdict = "PHISHING" if rule_score >= 45 else "LEGITIMATE"
        engine = "rule-based"

    risk_score = max(0, min(100, risk_score))

    elapsed_ms = round((time.perf_counter() - t0) * 1000)

    return {
        "scan_id": str(uuid.uuid4())[:8],
        "url": url,
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "risk_score": risk_score,
        "engine": engine,
        "features": features,
        "feature_details": {
            "protocol": meta["protocol"],
            "hostname": meta["hostname"],
            "tld": meta["tld"],
            "domain": meta["domain"],
            "suspicious_keywords": meta["suspicious_keywords"],
            "domain_created": meta["domain_created"],
        },
        "breakdown": {
            "url_score": breakdown_result["url_score"],
            "domain_score": breakdown_result["domain_score"],
            "content_score": breakdown_result["content_score"],
            "behavioral_score": breakdown_result["behavioral_score"],
        },
        "flags": breakdown_result["flags"],
        "shap_values": shap_values,
        "extraction_time_ms": elapsed_ms,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": _model is not None,
        "engine": _engine_name,
    }


@app.get("/")
async def root():
    return {"message": "PhishGuard API is running. POST to /api/v1/analyze"}

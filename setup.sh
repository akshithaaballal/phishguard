#!/usr/bin/env bash
# PhishGuard — one-shot setup script
# Run from the phishguard/ directory: bash setup.sh

set -e
echo "==============================="
echo "  PhishGuard Setup"
echo "==============================="

# 1. Install Python dependencies
echo ""
echo "→ Installing Python dependencies..."
pip install -r requirements.txt

# 2. Train the ML model
echo ""
echo "→ Training ML model..."
python3 -m app.train_model

# 3. Done
echo ""
echo "==============================="
echo "  Setup complete!"
echo "  Run the server with:"
echo ""
echo "  uvicorn app.main:app --reload --port 8000"
echo ""
echo "  Then open PHISHGAURD.html in your browser."
echo "==============================="

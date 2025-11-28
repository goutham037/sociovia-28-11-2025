#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -o errexit

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run database migrations (if using Alembic or Flask-Migrate)
# Uncomment if you set up Alembic
# alembic upgrade head

# Export environment variables
export FLASK_APP=test.py
export FLASK_ENV=production

# Start Flask server (Render expects it to bind 0.0.0.0:$PORT)
flask run --host=0.0.0.0 --port=$PORT


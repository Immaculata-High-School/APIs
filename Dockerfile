FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask \
    requests \
    beautifulsoup4 \
    lxml \
    flask-sqlalchemy \
    psycopg2-binary \
    cryptography \
    gunicorn

# Copy application code
COPY . .

# Create static and templates directories if they don't exist
RUN mkdir -p static templates

# Create data directory for SQLite persistence
RUN mkdir -p /data

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Volume for SQLite database persistence (when not using PostgreSQL)
VOLUME ["/data"]

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "app:app"]

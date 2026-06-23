FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY *.py ./

# Run as a non-root user.
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

# Documentation only; the app binds 0.0.0.0:$PORT (default 8000).
EXPOSE 8000

# Entry point reads HOST/PORT (and all other settings) from the environment.
CMD ["python", "app.py"]

FROM python:3.11-slim

WORKDIR /app

# Create non-root system group and user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy requirements and install dependencies
COPY backend/requirements.txt backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend code and sanitized dataset
COPY backend/ backend/
COPY dataset/ dataset/

# Ensure non-root appuser owns /app and data directories
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

CMD ["bash", "-c", "python -m backend.run_scan && uvicorn backend.main:app --host 0.0.0.0 --port 8000"]

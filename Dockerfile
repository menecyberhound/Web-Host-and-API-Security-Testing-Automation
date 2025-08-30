FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for database and logs
RUN mkdir -p /data /app/logs

# Set environment variables
ENV DB_PATH=/data/scan_results.db
ENV PYTHONUNBUFFERED=1

# Set proper ownership
RUN chown -R 1000:1000 /app /data

EXPOSE 5000

CMD ["python", "app.py"]

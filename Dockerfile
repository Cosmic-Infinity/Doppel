FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY doppel/ ./doppel/
COPY config.yaml ./config.yaml
COPY README.md ./

# Create data directories
RUN mkdir -p /app/data /app/reports

EXPOSE 2222

ENTRYPOINT ["python", "-m", "doppel.cli"]
CMD ["run"]

FROM python:3.11.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install torch CPU first to save ~800MB of image size and speed up build
RUN pip install --no-cache-dir torch>=2.0.0 --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

COPY . .

RUN useradd -m -u 1000 ids
RUN mkdir -p models && chown ids:ids models

EXPOSE 8000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER ids

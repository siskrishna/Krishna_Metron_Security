# Use official Python slim image
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Do not expose secrets in Dockerfile
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "main.py"]

# Lightweight Python image
FROM python:3.12-slim

# Prevents Python from writing .pyc files and enables unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy the rest of the source
COPY . .

# Default process (matches Procfile: worker: python bot.py)
CMD ["python", "bot.py"]


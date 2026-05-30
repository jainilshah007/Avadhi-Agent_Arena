FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for slither/solc
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install solc-select and slither; pre-install common Solidity versions
RUN pip install --no-cache-dir solc-select slither-analyzer \
    && solc-select install 0.8.28 \
    && solc-select install 0.8.20 \
    && solc-select install 0.8.17 \
    && solc-select install 0.8.13 \
    && solc-select install 0.7.6 \
    && solc-select install 0.6.12 \
    && solc-select use 0.8.28

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE ${PORT:-8000}

CMD ["/bin/sh", "-c", "python -m avadhi serve --port ${PORT:-8000}"]

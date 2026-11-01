# Hybrid OSINT MCP workstation
# Pure-Python always works; binaries preinstalled for full hybrid mode.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OSINT_ALLOW_ACTIVE=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential \
        nmap libimage-exiftool-perl \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery subfinder
ENV GOPATH=/opt/go
ENV PATH="${PATH}:/opt/go/bin"
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

WORKDIR /app
COPY pyproject.toml requirements.txt README.md ./
COPY osint_mcp ./osint_mcp
COPY docs ./docs

RUN pip install --upgrade pip \
    && pip install -e . \
    && pip install "sherlock-project>=0.15.0" "maigret>=0.4.4" "holehe>=1.61" \
       "dnstwist>=20240812" \
    && (pip install "theHarvester>=4.6.0" || pip install theHarvester || true)

# Non-root
RUN useradd -m -u 1000 osint
USER osint
WORKDIR /home/osint

ENTRYPOINT ["osint-mcp"]

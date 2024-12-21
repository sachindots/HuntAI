# HuntAI recon sandbox — tools run here, never on the host.
# Debian slim base + classic scanners + the ProjectDiscovery suite (pinned).
# Phase 2 wires these behind MCP with typed parsers.

FROM debian:bookworm-slim

ARG PD_HTTPX=1.6.9
ARG PD_NAABU=2.3.1
ARG PD_SUBFINDER=2.6.6
ARG PD_NUCLEI=3.3.4

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        dnsutils \
        curl \
        wget \
        ca-certificates \
        netcat-openbsd \
        whatweb \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery static binaries (arch-aware)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) pd=amd64;; arm64) pd=arm64;; *) pd=amd64;; esac; \
    cd /tmp; \
    for pair in \
        "httpx:${PD_HTTPX}" \
        "naabu:${PD_NAABU}" \
        "subfinder:${PD_SUBFINDER}" \
        "nuclei:${PD_NUCLEI}" ; do \
        name="${pair%%:*}"; ver="${pair##*:}"; \
        url="https://github.com/projectdiscovery/${name}/releases/download/v${ver}/${name}_${ver}_linux_${pd}.zip"; \
        wget -q "$url" -O "${name}.zip"; \
        unzip -o -q "${name}.zip" "${name}" -d /usr/local/bin/; \
        chmod +x "/usr/local/bin/${name}"; \
        rm -f "${name}.zip"; \
    done

WORKDIR /work

# non-root user for tool execution
RUN useradd -m -u 1000 hunter
USER hunter

CMD ["sleep", "infinity"]

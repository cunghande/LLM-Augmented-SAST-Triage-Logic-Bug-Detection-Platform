FROM docker:29.7.1-cli AS docker_cli

FROM python:3.12.12-slim-bookworm

ARG GITLEAKS_VERSION=8.30.1
ARG SEMGREP_VERSION=1.170.0

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=docker_cli /usr/local/bin/docker /usr/local/bin/docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --location --retry 3 \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        --output /tmp/gitleaks.tar.gz \
    && curl --fail --location --retry 3 \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
        --output /tmp/gitleaks-checksums.txt \
    && grep " gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz$" /tmp/gitleaks-checksums.txt \
        | sed 's|gitleaks_[^ ]*_linux_x64.tar.gz|/tmp/gitleaks.tar.gz|' \
        | sha256sum --check --strict \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz /tmp/gitleaks-checksums.txt

WORKDIR /opt/sast-triage

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts/docker-doctor.sh /usr/local/bin/sast-triage-doctor

RUN python -m pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" . \
    && chmod 0755 /usr/local/bin/sast-triage-doctor \
    && sast-triage --help >/dev/null \
    && semgrep --version \
    && gitleaks version \
    && docker --version

ENTRYPOINT ["sast-triage"]
CMD ["--help"]

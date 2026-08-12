FROM ubuntu:26.04

ARG JOERN_VERSION=v4.0.600
ARG JOERN_SHA256=5463a7cb3462cc95b76656d614001e95a4c5bddb3563b021e5ec4cecbed536ba

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        openjdk-21-jre-headless \
        python3 \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --retry 3 \
        "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli-linux-x86_64.zip" \
        --output /tmp/joern.zip \
    && echo "${JOERN_SHA256}  /tmp/joern.zip" | sha256sum --check --strict \
    && mkdir -p /opt/joern \
    && unzip -q /tmp/joern.zip -d /opt/joern \
    && rm /tmp/joern.zip \
    && JOERN_BIN="$(find /opt/joern -type f -name joern -perm /111 | head -n 1)" \
    && test -n "${JOERN_BIN}" \
    && JOERN_HOME="$(dirname "${JOERN_BIN}")" \
    && ln -s "${JOERN_HOME}/joern" /usr/local/bin/joern \
    && ln -s "${JOERN_HOME}/joern-parse" /usr/local/bin/joern-parse

WORKDIR /workspace

EXPOSE 8080

ENTRYPOINT ["joern"]
CMD ["--server", "--server-host", "0.0.0.0"]

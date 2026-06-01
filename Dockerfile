FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/zero ./cmd/zero
ARG WEBANALYZE_VERSION=0.4.1
RUN go install github.com/rverton/webanalyze/cmd/webanalyze@v${WEBANALYZE_VERSION} && \
    mkdir -p /out/webanalyze && \
    cd /out/webanalyze && \
    /go/bin/webanalyze -update -silent && \
    cp /go/bin/webanalyze /out/webanalyze/webanalyze

FROM alpine:3.21

ARG TARGETARCH
ARG SUBFINDER_VERSION=2.14.0
ARG HTTPX_VERSION=1.9.0
ARG NUCLEI_VERSION=3.8.0

RUN apk add --no-cache ca-certificates bind-tools git curl unzip && \
    adduser -D -h /home/zero zero && \
    mkdir -p /home/zero/.config/subfinder && \
    chown -R zero:zero /home/zero

RUN set -eux; \
    case "${TARGETARCH}" in amd64|arm64) arch="${TARGETARCH}" ;; *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; esac; \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip" -o /tmp/subfinder.zip; \
    unzip -q /tmp/subfinder.zip -d /tmp/subfinder; \
    install -m 0755 /tmp/subfinder/subfinder /usr/local/bin/subfinder; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${arch}.zip" -o /tmp/httpx.zip; \
    unzip -q /tmp/httpx.zip -d /tmp/httpx; \
    install -m 0755 /tmp/httpx/httpx /usr/local/bin/httpx; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip" -o /tmp/nuclei.zip; \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/subfinder /tmp/subfinder.zip /tmp/httpx /tmp/httpx.zip /tmp/nuclei /tmp/nuclei.zip

COPY --from=build /out/zero /usr/local/bin/zero
COPY --from=build /out/webanalyze/webanalyze /usr/local/bin/webanalyze
COPY --from=build /out/webanalyze/technologies.json /usr/local/share/webanalyze/technologies.json
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER zero
WORKDIR /home/zero

ENV ZERO_SUBFINDER_BIN=/usr/local/bin/subfinder
ENV ZERO_HTTPX_BIN=/usr/local/bin/httpx
ENV ZERO_WEBANALYZE_BIN=/usr/local/bin/webanalyze
ENV ZERO_WEBANALYZE_APPS=/usr/local/share/webanalyze/technologies.json
ENV ZERO_NUCLEI_BIN=/usr/local/bin/nuclei
ENV ZERO_SUBFINDER_PROVIDER_CONFIG=/home/zero/.config/subfinder/provider-config.yaml

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["worker"]

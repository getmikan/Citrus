FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS builder
ARG TARGETPLATFORM
RUN echo "I'm building for $TARGETPLATFORM"

RUN apk add --no-cache gzip && \
    mkdir /citrus-config && \
    wget -O /citrus-config/geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    wget -O /citrus-config/geosite.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat && \
    wget -O /citrus-config/geoip.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat

COPY docker/file-name.sh /citrus/file-name.sh
WORKDIR /citrus
COPY bin/ bin/
RUN FILE_NAME="$(sh file-name.sh).gz" && \
    gzip -dc "bin/$FILE_NAME" > citrus && chmod +x citrus
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
LABEL org.opencontainers.image.source="https://github.com/getmikan/Citrus"

RUN apk add --no-cache ca-certificates tzdata iptables

VOLUME ["/root/.config/citrus/"]

COPY --from=builder /citrus-config/ /root/.config/citrus/
COPY --from=builder /citrus/citrus /citrus
ENTRYPOINT [ "/citrus" ]

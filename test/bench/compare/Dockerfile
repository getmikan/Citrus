# Runtime image of the comparison: the four servers, the clients (Xray,
# sing-box) and the cmp tool. The build context is .build/ (run.sh fills
# .build/bin).
FROM alpine:3.24.2
COPY bin/xray bin/sing-box bin/mihomo bin/citrus bin/cmp /opt/bin/
COPY bin/*.version /opt/bin/

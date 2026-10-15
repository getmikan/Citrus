# Runtime image of the comparison: the three servers, the Xray client and the
# cmp tool. The build context is .build/ (run.sh fills .build/bin).
FROM alpine:3.24.2
COPY bin/xray bin/mihomo bin/citrus bin/cmp /opt/bin/
COPY bin/*.version /opt/bin/

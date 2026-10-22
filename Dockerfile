# Build the node entirely inside Docker. The host needs no Go toolchain.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/xmesh-node .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S -g 10001 xmesh && adduser -S -D -H -u 10001 -G xmesh xmesh
COPY --from=build /out/xmesh-node /usr/local/bin/xmesh-node
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/xmesh-node"]
CMD ["-config", "/etc/xmesh-node/config.json"]

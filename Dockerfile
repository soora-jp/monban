FROM golang:1.27.4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY LICENSE ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/soora-jp/monban/internal/monban.version=${VERSION}" \
    -o /monban ./cmd/monban

# Bundle the license and notice files of Go and every module linked into the binary.
RUN set -eu; \
    mkdir -p /licenses/golang; \
    cp LICENSE /licenses/; \
    cp "$(go env GOROOT)/LICENSE" "$(go env GOROOT)/PATENTS" /licenses/golang/; \
    go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}' ./cmd/monban | sort -u | \
    while read -r path dir; do \
      mkdir -p "/licenses/$path"; \
      cp "$dir"/LICENSE* "$dir"/NOTICE* "/licenses/$path/" 2>/dev/null || true; \
      ls "/licenses/$path"/LICENSE* > /dev/null; \
    done

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/soora-jp/monban" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Lightweight FQDN-filtering egress proxy for Kubernetes" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /monban /monban
COPY --from=build /licenses /licenses
USER 65532:65532
EXPOSE 8888 9090
ENTRYPOINT ["/monban"]

FROM golang:1.25.12-alpine AS build

RUN apk add --no-cache ca-certificates

WORKDIR /src

COPY go.* ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/server \
    ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/migrate \
    ./cmd/migrate

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /server
COPY --from=build /out/migrate /migrate

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/server"]

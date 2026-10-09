FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/config-controller ./cmd/config-controller/main.go

FROM alpine:3.20

RUN apk --no-cache add ca-certificates curl
WORKDIR /app
COPY --from=builder /bin/config-controller /app/config-controller

EXPOSE 9091
ENTRYPOINT ["/app/config-controller"]

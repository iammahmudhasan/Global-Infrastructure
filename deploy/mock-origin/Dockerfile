FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/mock-origin main.go

FROM alpine:3.20

RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /bin/mock-origin /app/mock-origin

EXPOSE 8081 8082
ENTRYPOINT ["/app/mock-origin"]

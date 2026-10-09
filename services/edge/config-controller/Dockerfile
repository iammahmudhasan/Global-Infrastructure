ARG GOLANG_IMAGE=public.ecr.aws/docker/library/golang:1.23-alpine
ARG RUNTIME_IMAGE=public.ecr.aws/docker/library/alpine:3.20

FROM ${GOLANG_IMAGE} AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/config-controller ./cmd/config-controller/main.go

FROM ${RUNTIME_IMAGE}

RUN apk --no-cache add ca-certificates curl
WORKDIR /app
COPY --from=builder /bin/config-controller /app/config-controller

EXPOSE 9091
ENTRYPOINT ["/app/config-controller"]

ARG GOLANG_IMAGE=public.ecr.aws/docker/library/golang:1.23-alpine
ARG RUNTIME_IMAGE=public.ecr.aws/docker/library/alpine:3.20

FROM ${GOLANG_IMAGE} AS builder

WORKDIR /app
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/mock-origin main.go

FROM ${RUNTIME_IMAGE}

RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /bin/mock-origin /app/mock-origin

EXPOSE 8081 8082
ENTRYPOINT ["/app/mock-origin"]

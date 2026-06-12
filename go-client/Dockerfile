# Build Go binary
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o client .

# Get step CLI for ACME bootstrapping
FROM smallstep/step-cli:latest AS step-cli

# Final runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates openssh
COPY --from=step-cli /usr/local/bin/step /usr/local/bin/step
WORKDIR /app
COPY --from=builder /app/client .
# certs are mounted as volume (docker-compose.yml volumes: ./certs:/app/certs:ro)
EXPOSE 2222
CMD ["./client"]

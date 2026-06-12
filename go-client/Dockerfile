# Build Go binary
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o client .

# Final runtime image (step CLI replaced by Go ACME SDK)
FROM alpine:3.19
RUN apk add --no-cache ca-certificates openssh openssh-server openssh-sftp-server
WORKDIR /app
COPY --from=builder /app/client .
# certs are mounted as volume (docker-compose.yml volumes: ./certs:/app/certs:ro)
EXPOSE 22
CMD ["./client"]

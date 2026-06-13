# Build Go binary
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o client .

# Final runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates openssh openssh-server openssh-sftp-server
RUN adduser -D -s /bin/ash gateway-user
RUN ssh-keygen -A

WORKDIR /app
COPY --from=builder /app/client .
EXPOSE 22
# Start sshd in background, then run go-client in foreground
CMD ["./client"]

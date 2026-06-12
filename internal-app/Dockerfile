FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o internal-app main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/internal-app /app/internal-app
EXPOSE 80
CMD ["/app/internal-app"]
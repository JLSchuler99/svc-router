# Stage 1: Build the Go application
FROM golang:1.24.11-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./

# Download dependencies
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy the source code
COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -o router ./cmd/router/main.go

# Stage 2: Create a lightweight runtime image
FROM alpine:3.20

# Install ca-certificates for HTTPS for potential external api calls
RUN apk add --no-cache ca-certificates

# Set working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/router .

# Expose port 24454
EXPOSE 24454

# Command to run the application
CMD ["./router"]

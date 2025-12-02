# Runtime image - minimal image with kubectl and the debug-ward binary
# This expects the builder image to be built first using Dockerfile.build
FROM alpine:3.18

# Install kubectl and ca-certificates
RUN apk add --no-cache \
    ca-certificates \
    curl \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/kubectl \
    && apk del curl

# Copy the binary from builder image (built separately)
# The builder image must be built first: docker build -f Dockerfile.build -t kubectl-debug-ward-builder:latest .
COPY --from=kubectl-debug-ward-builder:latest /build/release/bin/kubectl-debug-ward-*/kubectl-debug-ward /usr/local/bin/kubectl-debug-ward

# Set working directory
WORKDIR /app

# Default command
ENTRYPOINT ["kubectl-debug-ward"]

# Use a lightweight Ubuntu image
FROM ubuntu:22.04

# Install build tools and OpenSSL
RUN apt-get update && \
    apt-get install -y g++ make libssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Default command: open a bash shell so you can build & run manually
CMD ["/bin/bash"]

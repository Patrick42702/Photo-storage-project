# Use a base image with C++ build tools
FROM gcc:14.2 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libmysqlcppconn-dev \
    cmake \
    git \
    libssl-dev \
    python3 \
    libasio-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install the latest version of CMake
RUN wget -qO- https://cmake.org/files/v3.27/cmake-3.27.4-linux-x86_64.tar.gz | tar --strip-components=1 -xz -C /usr/local

# Copy CMake files and source code
COPY CMakeLists.txt .
COPY main.cpp .
COPY .env .
COPY libs/ /app/libs/

# Debug: Verify GCC and CMake versions
RUN gcc --version && cmake --version

# Create build directory
RUN mkdir build

# Build the application
WORKDIR /app/build
RUN cmake .. && make

# Create final runtime image
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy the built executable from builder
# COPY --from=builder /app/build/photoapp /app/photoapp
COPY --from=builder /app/.env /app/build/.env

# Set working directory
WORKDIR /app/build

# Run the application
CMD ["./photoapp"]

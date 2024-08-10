FROM messense/rust-musl-cross:x86_64-musl AS builder
ENV SQLX_OFFLINE=true 
# ^ might not be necessary, given our setup
WORKDIR /grid-aware-server

# install OpenSSL
RUN apt-get update && apt-get install -y pkg-config libssl-dev

#set environment variables
ENV OPENSSL_DIR=/usr/lib/x86_64-linux-gnu
ENV OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
ENV OPENSSL_INCLUDE_DIR=/usr/include

# Copy the source code
COPY . .
# Build the application
RUN cargo build --release --target x86_64-unknown-linux-musl

# Create a new stage with a minimal image
FROM scratch
COPY --from=builder /grid-aware-server/target/x86_64-unknown-linux-musl/release/grid-aware-server /grid-aware-server
ENTRYPOINT ["/grid-aware-server"]
EXPOSE 3000
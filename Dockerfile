# Use official Rust image
FROM rust:latest

# Put all the test codes and folders in a folder called verification-tests
WORKDIR /verification-tests
COPY . .

# Run the tests
CMD ["cargo", "test", "--workspace"]

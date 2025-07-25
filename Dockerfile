FROM node:lts

# Install pnpm globally
RUN npm install -g pnpm

# Set working directory
WORKDIR /src

# Install common tools (required for Near)
RUN apt-get update && apt install -y git curl make git-all cmake gcc libssl-dev pkg-config libclang-dev libpq-dev build-essential

# Install Rust globally to /usr/local
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH="/src/.cargo/bin:/usr/local/cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.3 -LsSf https://sh.rustup.rs | sh -s -- -y --no-modify-path && chmod -R a+w /usr/local/rustup /usr/local/cargo

# Install NEAR CLI-RS
RUN curl --proto '=https' --tlsv1.3 -LsSf https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.sh | sh

# Install cargo-near
RUN curl --proto '=https' --tlsv1.3 -LsSf https://github.com/near/cargo-near/releases/latest/download/cargo-near-installer.sh | sh

# Disable bash history
ENV HISTFILE=/dev/null
ENV HISTFILESIZE=0

# Default command
CMD ["/bin/bash"]

# Required to Stellar?
RUN apt install -y libudev-dev libdbus-1-dev jq

# Required for ICP?
RUN apt install -y libunwind-dev

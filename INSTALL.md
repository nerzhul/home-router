# Installation Guide

## System Installation

### 1. Build the Project

```bash
cargo build --release
```

### 2. Create User and Directories

```bash
# Create system user
sudo useradd -r -s /bin/false dhcp-server

# Create directories
sudo mkdir -p /etc/dhcp-server
sudo mkdir -p /var/lib/dhcp-server

# Set ownership
sudo chown dhcp-server:dhcp-server /var/lib/dhcp-server
```

### 3. Install Binaries

```bash
sudo cp target/release/dhcp-server /usr/local/bin/
sudo cp target/release/dhcp-cli /usr/local/bin/
sudo chmod +x /usr/local/bin/dhcp-server
sudo chmod +x /usr/local/bin/dhcp-cli

# Grant capability to bind to port 67
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/dhcp-server
```

### 4. Install Configuration

```bash
sudo cp config.example.yaml /etc/dhcp-server/config.yaml
sudo chown root:root /etc/dhcp-server/config.yaml
sudo chmod 644 /etc/dhcp-server/config.yaml

# Edit configuration as needed
sudo nano /etc/dhcp-server/config.yaml
```

### 5. Install Systemd Service

```bash
sudo cp dhcp-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dhcp-server
sudo systemctl start dhcp-server
```

### 6. Check Status

```bash
sudo systemctl status dhcp-server
sudo journalctl -u dhcp-server -f
```

## Usage

The CLI can be used by any user:

```bash
# List subnets
dhcp-cli subnet list

# Create a subnet
dhcp-cli subnet create \
  --network 192.168.1.0 \
  --netmask 24 \
  --gateway 192.168.1.1 \
  --dns-servers 8.8.8.8,8.8.4.4

# Add dynamic range
dhcp-cli range create \
  --subnet-id 1 \
  --start 192.168.1.100 \
  --end 192.168.1.200
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop dhcp-server
sudo systemctl disable dhcp-server

# Remove files
sudo rm /etc/systemd/system/dhcp-server.service
sudo rm /usr/local/bin/dhcp-server
sudo rm /usr/local/bin/dhcp-cli
sudo rm -rf /etc/dhcp-server
sudo rm -rf /var/lib/dhcp-server

# Remove user
sudo userdel dhcp-server

# Reload systemd
sudo systemctl daemon-reload
```

## Docker Installation

Alternatively, you can run in Docker:

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/dhcp-server /usr/local/bin/
COPY config.example.yaml /etc/dhcp-server/config.yaml
RUN mkdir -p /var/lib/dhcp-server
EXPOSE 67/udp 8080/tcp
CMD ["/usr/local/bin/dhcp-server"]
```

Build and run:

```bash
docker build -t dhcp-server .
docker run -d \
  --name dhcp-server \
  -p 67:67/udp \
  -p 8080:8080 \
  -v /etc/dhcp-server:/etc/dhcp-server \
  -v /var/lib/dhcp-server:/var/lib/dhcp-server \
  dhcp-server
```

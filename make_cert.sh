#!/bin/sh
# Create a self-signed certificate for the TLS demo (valid 1 year).
# Output: server.crt (give to clients) and server.key (keep on the server).
set -e
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=lanchat" -keyout server.key -out server.crt
chmod 600 server.key
echo "Created server.crt and server.key"

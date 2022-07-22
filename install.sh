#! /bin/bash

echo "Installing...";
# Check if go is installed?
command -v go >/dev/null 2>&1 || { echo >&2 "Please install go first: https://go.dev/dl/ and add it to your path"; exit 1; } 
mkdir -p ~/go/bin
cp index.html ~/go/bin;
mkdir -p ~/go/bin/public
cp ./public/index.html ~/go/bin/public
go install .;
# Generate SSH Cert
echo "Generating Server Certificates in ~/go/bin: "
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out ~/go/bin/server.crt -keyout ~/go/bin/server.key -subj "/C=US/ST=Texas/L=Austin/O=Sundquist/OU=DevOps/CN=localhost"
# Generate mTLS Cert 
echo "Generating Client Certificates in ~/go/bin: "
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out ~/go/bin/client.crt -keyout ~/go/bin/client.key -subj "/C=US/ST=Texas/L=Austin/O=Sundquist/OU=DevOps/CN=localhost"

### Install as service? 

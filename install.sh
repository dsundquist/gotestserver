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
openssl req  -new  -newkey rsa:2048  -nodes  -keyout ~/go/bin/server.key  -out ~/go/bin/server.csr
openssl  x509  -req  -days 365  -in ~/go/bin/server.csr  -signkey ~/go/bin/server.key  -out ~/go/bin/server.crt
# Generate mTLS Cert 
echo "Generating Client Certificates in ~/go/bin: "
openssl req  -new  -newkey rsa:2048  -nodes  -keyout ~/go/bin/client.key  -out ~/go/bin/client.csr
openssl  x509  -req  -days 365  -in ~/go/bin/server.csr  -signkey ~/go/bin/client.key  -out ~/go/bin/client.crt

### Install as service? 
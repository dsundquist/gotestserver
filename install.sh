#! /bin/bash

echo "Installing...";
# Check if go is installed? 
# mkdir -p ~/go/bin
cp index.html ~/go/bin;
# mkdir -p ~/go/bin/public
# cp ./public/index.html ~/go/bin/public
# go install .;
# Generate SSH Cert
#openssl req  -new  -newkey rsa:2048  -nodes  -keyout server.key  -out server.csr
#openssl  x509  -req  -days 365  -in server.csr  -signkey server.key  -out server.crt
# Generate mTLS Cert 
#openssl req  -new  -newkey rsa:2048  -nodes  -keyout client.key  -out client.csr
#openssl  x509  -req  -days 365  -in server.csr  -signkey client.key  -out client.crt
# Cleanup Certs
# rm -f server.key server.cert server.csr client.key client.crt client.csr 

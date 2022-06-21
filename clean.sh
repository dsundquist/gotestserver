#! /bin/bash

# Cleanup Certs

echo "Attempting to remove the following: ~/go/bin/server.key ~/go/bin/server.crt ~/go/bin/server.csr ~/go/bin/client.key ~/go/bin/client.crt ~/go/bin/client.csr  "
rm -f ~/go/bin/server.key ~/go/bin/server.crt ~/go/bin/server.csr ~/go/bin/client.key ~/go/bin/client.crt ~/go/bin/client.csr 
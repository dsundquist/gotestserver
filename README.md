# GoTestServer

This tool was designed for troubleshooting requests when behind a reverse proxy, primarily Cloudflare.  It is a personal project that I use as a Technical Support Engineer. It can also be placed behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/) and [cloudflared Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) for troubleshooting. 

### There are 4 certs that are included as examples, please delete these if you're running this in production 

## Install 

Install Go: [Go - Download and install](https://go.dev/doc/install)

```
go install github.com/dsundquist/gotestserver@latest
```

## Usage 

To run the basic webserver (assuming that you haven't yet added `~/go/bin` directory to your path, and that you'll be using the default port 80 which will require sudo): 

```
sudo ~/go/bin/gotestserver serve
```

If you wish to not use the default port of 80, you can start the http server on alternate port using the -p flag.

```
~/go/bin/gotestserver serve -p 8080
```

If you want to run an https server you can use the defaults that are included in the repo.  You should replace these with the following: 

```
openssl req  -new  -newkey rsa:2048  -nodes  -keyout server.key  -out server.csr
openssl  x509  -req  -days 365  -in server.csr  -signkey server.key  -out server.crt
```

The 2x files `server.crt` and `server.key` should be in the same directory has `./gotestserver`: 

```
* local_directory: 
   |-> gotestserver
   |
   |-> server.crt 
   |-> server.key 
```

Then one can run the serve command with a -s flag: 

```
sudo ~/go/bin/gotestserver serve -s
```

The CLI is built from [Cobra](https://github.com/spf13/cobra), to see additional usage use the --help flag: 

```
./gotestserver serve --help
```

## HTTP Server Behavior 

The main page will serve `./index.html`.

Any pages that are not found, (besides the `/public` directory, which acts as a normal webserver) will return the request headers. 

This can be useful for analysis when behind a reverse proxy or a product like [Cloudflared](https://github.com/cloudflare/cloudflared) 

## The 522 Error Page

A 522 error is defined here: [Cloudflare Support - 522 Error](https://support.cloudflare.com/hc/en-us/articles/115003011431-Troubleshooting-Cloudflare-5XX-errors#522error)

The error occurs at the network level when: 

1. Before a connection is established, the origin web server does not return a SYN+ACK to Cloudflare within 15 seconds of Cloudflare sending a SYN.
2. After a connection is established, the origin web server doesn’t acknowledge (ACK) Cloudflare’s resource request within 90 seconds.

Therefore we cannot complete this from the same server, as we need to sabatoge the server at the network level.  In my implementation I have another simple http server listening on port 80, in which I'm redirect requests over to.  At that server I've added an iptables drop rule that is dropping all ack packets to the listening port, recreated #2 above. 

```
dsundquist:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -i eth1 -p tcp -m tcp --dport 80 -j DROP
-A INPUT -i eth0 -p tcp -m tcp --dport 80 -j DROP
```

For that sabatoged HTTP server, I also have it programmed to 30 seconds, and two routes to reach it, one via its normal IP address (behind Cloudflare) and one over a [cloudflared tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)

## Todo

* Add more to the client side, this is still up in the air what will happen here. 
* Workers for some routes, worker serve the index.html?? 
* Read from a config.yaml file [SPF13 - Viper](https://github.com/spf13/viper)
* Write debugging to a file, https://stackoverflow.com/questions/19965795/how-to-write-log-to-file
* Can we force to an http version? ie. http1.0, http1.1, http2, https://stackoverflow.com/questions/53367809/how-to-force-client-to-use-http-2-instead-of-falling-back-to-http-1-1
* Implement QUIC,  https://pkg.go.dev/github.com/lucas-clemente/quic-go/http3

* Document: 
  * mTLS
  * Necessary file structure for all functions to work  
  * The public folder
  * debugging
  * Client and its uselessness 
  * Response, ie `localhost/response?header1=value1&header2=value2`
  

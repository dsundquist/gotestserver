# Go httperrors 

This tool was designed for troubleshooting requests when behind a reverse proxy, primarily Cloudflare.  It is a personal project that I use as a Technical Support Engineer. It can also be placed behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/) and [cloudflared Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) for troubleshooting. 

## Install 

```
go install github.com/dsundquist/httperrors@latest
```

## Usage 

To run the basic webserver (assuming that you haven't yet added `~/go/bin` directory to your path, and that you'll be using the default port 80 which will require sudo): 

```
sudo ~/go/bin/httperrors serve
```

If you wish to not use the default port of 80, you can start the http server on alternate port using the -p flag.

```
~/go/bin/httperrors serve -p 8080
```

If you want to run an https server you'll need a self signed certificate.  You can run the following 2x commands: 

```
openssl req  -new  -newkey rsa:2048  -nodes  -keyout server.key  -out server.csr
openssl  x509  -req  -days 365  -in server.csr  -signkey server.key  -out server.crt
```

The 2x files `server.crt` and `server.key` should be in the same directory has `./httperrors`: 

```
* local_directory: 
   |-> httperrors
   |
   |-> server.crt 
   |-> server.key 
```

Then one can run the serve command with a -s flag: 

```
sudo ~/go/bin/httperrors serve -s
```

The CLI is built from [Cobra](https://github.com/spf13/cobra), to see additional usage use the --help flag: 

```
./httperrors serve --help
```

## HTTP Server Behavior 

The main page will just return back the request headers that the server had received.  This can be useful for analysis when behind a reverse proxy or a product like [Cloudflared](https://github.com/cloudflare/cloudflared) 

To use generate 5xx errors, for troubleshooting behind Cloudflare, visit: 

```
http://localhost/help
```

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
* Read from a config.yaml file [SPF13 - Viper](https://github.com/spf13/viper)
* Write debugging to a file, https://stackoverflow.com/questions/19965795/how-to-write-log-to-file
* Implement QUIC,  https://pkg.go.dev/github.com/lucas-clemente/quic-go/http3
* Update the main page to return, port that it hit, along with HTTP version, 

* gotestserver.com - Going to start moving this project over to this url, likely rename the repo to gotestserver
  * tunnel.gotestserver.com - behind a cloudflare tunnels
  * access.gotestserver.com - behind access
  * 522.gotestserver.com - Serve the 522 error page
  * quic.gotestserver.com - Serve QUIC - we could do this by a normal port (ie. 8080), or create a worker, https://pkg.go.dev/net/http#Request

* Document: 
  * mTLS
  * Necessary file structure for all functions to work  
  * The public folder
  * debugging
  * Client and its uselessness 
  * Response, ie `localhost/response?header1=value1&header2=value2`
  

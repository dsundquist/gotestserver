# Go httperrors Server 

This tool was designed for troubleshooting requests when behind a reverse proxy, primarily Cloudflare.  It is a personal project that I use as a Technical Support Engineer.

To install: 

```
go install github.com/dsundquist/httperrors@latest
```

To run the basic webserver (assuming that haven't you yet added `~/go/bin` directory to your path, and that you'll be using the default port 80 which will require sudo): 

```
sudo ~/go/bin/httperrors serve
```

After the server is running you can visit: 

```
http://localhost
```

The main page will just return back the request headers that the server had received.  This can be useful for analysis when behind a reverse proxy or a product like [Cloudflared](https://github.com/cloudflare/cloudflared) 

To use generate 5xx errors, for troubleshooting behind Cloudflare, visit: 

```
http://localhost/help
```

### Todo: 

* Add TLS support
* Ability to specify a port other than the default


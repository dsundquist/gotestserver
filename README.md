# Go httperrors Server 

The main page (/) does not actually generate any errors.  

It simply returns back to the user the request headers (and connecting host) that it had received. 

It's particularly useful when the webserver is behind a proxy, so that one can inspect them for troubleshooting purposes.

Additionally if you visit /help you will find links to other locations which purposefully generate 5xx (Cloudflare specific) errors.  This also can be particularly useful when troubleshooting locations behind a proxy. 

This tool was primarily designed to troubleshoot locations behind the Cloudflare proxy and [Cloudflared](https://github.com/cloudflare/cloudflared)

/*
Copyright © 2022 Dean Sundquist dean@sundquist.net

*/
package cmd

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)


// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the httperrors webserver",
	Long:  `Use this command to start the webserver, at this time it will use port 80`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("serve called")
		port, _ := cmd.Flags().GetInt("port")
		fmt.Printf("Starting Server on port: %v\n", port)
		serve(port)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func serve(port int) {

	http.HandleFunc("/", PrintHeaders) // Default prints request headers
	http.HandleFunc("/help", Help)
	http.HandleFunc("/cors", Cors)
	http.HandleFunc("/setcookie", Setcookies)
	http.HandleFunc("/403", Fourohthree)
	http.HandleFunc("/404", Fourohfour)
	http.HandleFunc("/405", Fourohfive)
	http.HandleFunc("/500", Fivehundred)
	http.HandleFunc("/502", Fiveohtwo)
	http.HandleFunc("/503", Fiveohthree)
	http.HandleFunc("/504", Fiveohfour)
	http.HandleFunc("/520", Fivetwenty)
	http.HandleFunc("/524", Fivetwentyfour)

	location := ":" + strconv.Itoa(port)

	log.Fatal(http.ListenAndServe(location, nil))
}

func PrintHeaders(w http.ResponseWriter, req *http.Request) {

	var response string

	response += "Hello from a very basic Go HTTPS server implementation! ;)\n\n"

	response += fmt.Sprintf("Remote Address: %v\n\n", req.RemoteAddr)

	response += fmt.Sprintf("Host: %v \n", req.Host)

	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)

	for name, values := range req.Header {
		// Loop over all values for the name.
		for _, value := range values {
			response += fmt.Sprintf("Header: %v Value: %v \n", name, value)
		}
	}

	fmt.Fprintf(w, "%v\n", response)
}

func Help(w http.ResponseWriter, req *http.Request) {

	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)

	var response string

	w.Header().Add("Content-Type", "text/html")

	response += "<h2>Available Locations: </h2>\n"
	response += "\t <a href =\"/403\">/403</a><br>\n"
	response += "\t <a href =\"/404\">/404</a><br>\n"
    response += "\t <a href =\"/405\">/405</a><br>\n" 
	response += "\t <a href =\"/500\">/500</a><br>\n"
	response += "\t <a href =\"/502\">/502</a><br>\n"
	response += "\t <a href =\"/503\">/503</a><br>\n"
	response += "\t <a href =\"/504\">/504</a><br>\n"
	response += "\t <a href =\"/520\">/520</a><br>\n"
	response += "\t <a href =\"/524\">/524</a><br>\n"

    // 522 is an error that occurs at the networking level
    // It is outlined here: 
    // https://support.cloudflare.com/hc/en-us/articles/115003011431-Troubleshooting-Cloudflare-5XX-errors#522error
	// So we'll be redirecting over to another server that is has an iptables rule set to drop ack packets to port 80,
    // where we have a basic http server listening on that port. 
    // ~$ sudo iptables -S
    // -P INPUT ACCEPT
    // -P FORWARD ACCEPT
    // -P OUTPUT ACCEPT
    // -A INPUT -i eth1 -p tcp -m tcp --dport 80 -j DROP
    // -A INPUT -i eth0 -p tcp -m tcp --dport 80 -j DROP
    response += "Other: <br>\n"
	response += "\t <a href =\"https://522.sundquist.net/\">522 - No tunnel</a><br>\n"
	response += "\t <a href =\"https://522-tunnel.sundquist.net/\">522 - With tunnel</a><br>\n"
    response += "\t <a href =\"/setcookie\">Set Cookie - returns a cookie for testing through proxy, Access, and/or cloudflared</a><br>\n"

	fmt.Fprintf(w, "%v\n", response)
}


// An experiment playing with an issue in Cloudflare Access where an application behind Access is attempting to call
// a second application which is also behind Access.  This is currently not supported.  We call this Single Page Apps. 
func Cors(w http.ResponseWriter, req *http.Request) {

	var response string

	w.Header().Add("Content-Type", "text/html")
	//  w.Header().Add("Access-Control-Allow-Origin","https://one.tun.sundquist.net")
	//  w.Header().Add("Access-Control-Max-Age","60")
	w.Header().Add("Access-Control-Allow-Credentials", "true")

	response += "" +
		"\n\n\n\n\n Next Fetch \n\n" +
		"<script crossorigin=\"use-credentials\">" +
		"console.log(\"Testing2\");" +
		"\n" +
		"const myHeaders = new Headers ({'X-Custom-Header':'Hello-World'});" +
		"fetch('https://one.tun.sundquist.net/setcookie', {headers: {}, credentials: 'include'});" +
		"fetch('https://one.tun.sundquist.net/', {headers: {}, credentials: 'include'});" +
		"fetch('https://two.tun.sundquist.net/', {headers: {myHeaders}, credentials: 'include'});" +
		//  "fetch('https://two.tun.sundquist.net/', {credentials: 'include'});" +
		"</script>"

	fmt.Fprintf(w, "%v\n", response)

}

// Set Cookie
// I original had attempted to play with the CF_Authorization Cookie, to see if I could rescope it to the apex domain.
// That had no impact, and it is now commented out (Might get back to this experiment). 
// What now exists is a simple ability to set a cookie. 
// This can be used to test set-cookie behind a proxy.
func Setcookies(w http.ResponseWriter, req *http.Request) {

/*
	w.Header().Add("Access-Control-Allow-Credentials", "true")
	w.Header().Add("cache-control", "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0")

	myCookie, err := req.Cookie("CF_Authorization")
	if err != nil {
		log.Println("No Cookies\n")
		return
	}

	myCookie.Domain = "sundquist.net"
	myCookie.HttpOnly = true
	myCookie.Secure = true
	myCookie.SameSite = 4
	myCookie.Path = "/"
	myCookie.MaxAge = 600
	log.Println(myCookie)
	http.SetCookie(w, myCookie)
*/

  // Set the expiration date one year in the future, create a cooke and set it.  
  // https://go.dev/src/net/http/cookie.go 
  expiration := time.Now().Add(365 * 24 * time.Hour)
  cookie := http.Cookie{} //{Name: "my_custom_cookie",Value:"abcd",Expires:expiration}
  cookie.Name = "my_custom_cookie" 
  cookie.Value = "abcd"
  cookie.Expires = expiration
  http.SetCookie(w, &cookie)

  // Redirect w/ cookie, uncomment the next line if you want to redirect, but you'll need to remove the response
  // Or the Redirect will not happen 
  //http.Redirect(w, req, "https://gots-access.sundquist.net", 302)

  // Serving response, comment this out if you're using redirection above
  var response string
  response += "Setting Cookie:\n"
  response += "\tcookie.Name: %v\n"
  response += "\tcookie.Value: %v\n"
  response += "\tcookie.Path: %v\n"
  response += "\tcookie.Domain: %v\n"
  response += "\tcookie.Expires: %v\n"
  response += "\tcookie.MaxAge: %v\n"
  response += "\tcookie.Secure: %v\n"
  response += "\tcookie.HttpOnly: %v\n"
  response += "\tcookie.SameSite: %v\n"
  
  fmt.Fprintf(w, response, cookie.Name, cookie.Value, cookie.Path, cookie.Domain, cookie.Expires, cookie.MaxAge, cookie.Secure, cookie.HttpOnly, cookie.SameSite)


}

// 403
func Fourohthree(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(403)
}

// 404
func Fourohfour(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(404)
}

// 405
func Fourohfive(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(405)
}

// 500
func Fivehundred(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(500)
}

// 502
func Fiveohtwo(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(502)
}

// 503
func Fiveohthree(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(503)
}

// 504
func Fiveohfour(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(504)
}

// 520; Cloudflare Defines invalid response codes as a 520:
func Fivetwenty(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	w.WriteHeader(69)
}

// Cloudflare's timeout is 100 seconds so lets add just 1 second to the default
// If this becomes obnoxious, you could set the Timeout < 100 seconds
// Yes you can do this, most individual use this to increase the timout, but you *can* decrease it
// https://api.cloudflare.com/#zone-settings-change-proxy-read-timeout-setting
func Fivetwentyfour(w http.ResponseWriter, req *http.Request) {
	log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	time.Sleep(101 * time.Second)
}

/*
Copyright © 2022 Dean Sundquist dean@sundquist.net

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"log"
	"net/http"
	"strconv"
	"time"
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
	response += "\t <a href =\"/500\">/500</a><br>\n"
	response += "\t <a href =\"/502\">/502</a><br>\n"
	response += "\t <a href =\"/503\">/503</a><br>\n"
	response += "\t <a href =\"/504\">/504</a><br>\n"
	response += "\t <a href =\"/520\">/520</a><br>\n"
	response += "\t <a href =\"/524\">/524</a><br>\n"

	response += "Other: <br>\n"
	response += "\t <a href =\"https://522.sundquist.net/\">522 - No tunnel</a><br>\n"
	response += "\t <a href =\"https://522-tunnel.sundquist.net/\">522 - With tunnel</a><br>\n"

	fmt.Fprintf(w, "%v\n", response)
}

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

func Setcookies(w http.ResponseWriter, req *http.Request) {

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

// Cloudflare Defines, no response headers as a 520:
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

/*
Copyright © 2022 Dean Sundquist dean@sundquist.net
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
)

var debug bool = false

// Where the server will be runnining, ex localhost:8443
var location string

// A Mapping TLS Versison, uint -> ASCII  (doesn't exist in crypto/tls)
var tlsVersionsItoa = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}

// A Mapping TLS Versison, ASCII -> uint (doesn't exist in crypto/tls)
var tlsVersionsAtoi = map[string]uint16{
	"1.0": 0x0301,
	"1.1": 0x0302,
	"1.2": 0x0303,
	"1.3": 0x0304,
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the gotesterver",
	Long:  `Use this command to start the webserver, at this time it will use port 80`,
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		https, _ := cmd.Flags().GetBool("secure")
		mtls, _ := cmd.Flags().GetBool("mtls")
		cert, _ := cmd.Flags().GetString("cert")
		key, _ := cmd.Flags().GetString("key")
		clientCert, _ := cmd.Flags().GetString("clientcert")
		debug, _ = cmd.Flags().GetBool("debug")
		tlsMinVersion, _ := cmd.Flags().GetString("tlsMin")
		tlsMaxVersion, _ := cmd.Flags().GetString("tlsMax")
		ciphers, _ := cmd.Flags().GetString("ciphers")
		http1, _ := cmd.Flags().GetBool("http1")
		logfileloc, _ := cmd.Flags().GetString("logfile")

		if https || mtls {
			if port == 80 {
				fmt.Print("Found default port of 80 setting it to 443 for HTTPS Server\n")
				port = 443
			}
			fmt.Printf("Starting HTTPS Server on port: %v\n", port)
		} else {
			fmt.Printf("Starting HTTP Server on port: %v\n", port)
		}
		// fmt.Printf("Port: %v, https: %v, mtls: %v, cert: %v, key: %v, clientCert: %v\n", port, https, mtls, cert, key, clientCert)
		// Are we logging to a file?
		if logfileloc != "nil" {
			fmt.Printf("Found log file option for location: %v \n", logfileloc)
			logfile, err := os.OpenFile(logfileloc, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				log.Panic(err)
			}
			defer logfile.Close()

			// Set log out put and enjoy :)
			log.SetOutput(logfile)
		}

		serve(port, https, mtls, cert, key, clientCert, tlsMinVersion, tlsMaxVersion, ciphers, http1)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

// Start the Webserver with all of the parameters obtained
func serve(port int, https bool, mtls bool, cert string, key string, clientCert string, tlsMinVersion string, tlsMaxVersion string, ciphers string, http1 bool) {
	var err error

	http.HandleFunc("/", Request) // Default prints request headers
	http.HandleFunc("/cookie", Cookie)
	http.HandleFunc("/ip", Ip)
	http.HandleFunc("/readme", Readme)
	http.HandleFunc("/request", Request)
	http.HandleFunc("/longrequest", Longrequest)
	http.HandleFunc("/response", Response)
	http.HandleFunc("/public/", Servefiles)
	http.HandleFunc("/token_validate", TokenValidate)
	http.HandleFunc("/302", Threeohtwo)
	http.HandleFunc("/403", Fourohthree)
	http.HandleFunc("/404", Fourohfour)
	http.HandleFunc("/405", Fourohfive)
	http.HandleFunc("/500", Fivehundred)
	http.HandleFunc("/502", Fiveohtwo)
	http.HandleFunc("/503", Fiveohthree)
	http.HandleFunc("/504", Fiveohfour)
	http.HandleFunc("/520", Fivetwenty)
	http.HandleFunc("/524", Fivetwentyfour)

	location = ":" + strconv.Itoa(port)

	if mtls { // mTLS server (doesn't utlize all parameters) https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

		// Create a CA certificate pool and add cert.pem to it
		var caCert []byte
		caCert, err = ioutil.ReadFile(clientCert)
		if errors.Is(err, os.ErrNotExist) {
			log.Print("Please generate a client certificate:")
			log.Print("openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out client.crt -keyout client.key -subj \"/C=US/ST=Texas/L=Austin/O=Sundquist/OU=DevOps/CN=localhost\"")
			log.Fatal(err)
		} else if err != nil {
			log.Fatal(err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Create the TLS Config with the CA pool and enable Client certificate validation
		tlsConfig := &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}

		tlsConfig.BuildNameToCertificate()

		server := &http.Server{
			Addr:      location,
			TLSConfig: tlsConfig,
		}

		if http1 {
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		}

		err = server.ListenAndServeTLS(cert, key)

	} else if https { // The HTTPS Server

		var setTlsMinVersion uint16 = tls.VersionTLS10 // default would be 1.0
		for k, v := range tlsVersionsAtoi {
			if k == tlsMinVersion {
				setTlsMinVersion = v
			}
		}
		fmt.Printf("Using Minimum TLS version %v\n", tlsVersionsItoa[setTlsMinVersion])

		var setTlsMaxVersion uint16 = tls.VersionTLS13 // default would be 1.3
		for k, v := range tlsVersionsAtoi {
			if k == tlsMaxVersion {
				setTlsMaxVersion = v
			}
		}
		fmt.Printf("Using Maximum TLS version %v\n", tlsVersionsItoa[setTlsMaxVersion])

		if !(tlsMaxVersion >= tlsMinVersion) {
			log.Fatalf("The TLS maximum version: %v is not greater than the TLS minimum version: %v", tlsMaxVersion, tlsMinVersion)
		}

		var tlsCiphers []uint16
		var tlsCiphersStrings []string

		cipherSlice := strings.Split(ciphers, ",")

		for _, cipher := range cipherSlice {
			for _, availableCipher := range tls.CipherSuites() {
				if cipher == availableCipher.Name {
					tlsCiphers = append(tlsCiphers, availableCipher.ID)
					tlsCiphersStrings = append(tlsCiphersStrings, availableCipher.Name)
				}
			}
			for _, availableCipher := range tls.InsecureCipherSuites() {
				if cipher == availableCipher.Name {
					tlsCiphers = append(tlsCiphers, availableCipher.ID)
					tlsCiphersStrings = append(tlsCiphersStrings, availableCipher.Name)
				}
			}
		}

		if tlsCiphers != nil && tlsMaxVersion == "1.3" {
			fmt.Println("NOTE: Go ignores specified ciphers for TLS v1.3 connections.")
		}

		// Making this automatic, having strings was a bad original idea
		if ciphers != "nil" && (len(tlsCiphers) != len(cipherSlice)) {

			var errorMessage string

			// Print Secure Cipher Suites
			errorMessage += fmt.Sprintln("\nSecure Cipher Suites:")
			for _, cipher := range tls.CipherSuites() {
				errorMessage += fmt.Sprint("\t" + cipher.Name + ": ")
				// Available for these TLS Versions
				for _, j := range cipher.SupportedVersions {
					errorMessage += fmt.Sprint(tlsVersionsItoa[j] + " ")
				}
				errorMessage += fmt.Sprintln()
			}

			// Print Insecure Cipher Suites
			errorMessage += fmt.Sprintln("Insecure Cipher Suites:")
			for _, cipher := range tls.InsecureCipherSuites() {
				errorMessage += fmt.Sprint("\t" + cipher.Name + ": ")
				// Available for these TLS Versions
				for _, j := range cipher.SupportedVersions {
					errorMessage += fmt.Sprint(tlsVersionsItoa[j] + " ")
				}
				errorMessage += fmt.Sprintln()
			}

			log.Fatalf(errorMessage + "\nSee https://pkg.go.dev/crypto/tls")
		}

		fmt.Printf("Using ciphers (all available if blank): %v\n", tlsCiphersStrings)

		tlsConfig := &tls.Config{
			CipherSuites:             tlsCiphers,
			MinVersion:               setTlsMinVersion,
			MaxVersion:               setTlsMaxVersion,
			PreferServerCipherSuites: true,
		}

		tls.Listen("tcp", location, tlsConfig)

		server := &http.Server{
			Addr:      location,
			TLSConfig: tlsConfig,
		}

		if http1 {
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		}

		err = server.ListenAndServeTLS(cert, key)
		// err = http.ListenAndServeTLS(location, cert, key, nil)
	} else { // Normal HTTP Server
		err = http.ListenAndServe(location, nil)
	}

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			//https://medium.com/rungo/secure-https-servers-in-go-a783008b36da
			log.Print("Please generate a key and x509 certificate:")
			// From https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
			log.Print("openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out server.crt -keyout server.key -subj \"/C=US/ST=Texas/L=Austin/O=Sundquist/OU=DevOps/CN=localhost\"")
			// log.Print("\topenssl req  -new  -newkey rsa:2048  -nodes  -keyout server.key  -out server.csr")
			// log.Print("\topenssl  x509  -req  -days 365  -in server.csr  -signkey server.key  -out server.crt")
		}
		log.Fatal(err)
	}
}

func dumpRequest(req *http.Request) string {

	var response string

	response += fmt.Sprintln(time.Now().UTC())

	response += fmt.Sprintf("\nRemote Address: %v\n\n", req.RemoteAddr)
	response += fmt.Sprintf("Host: %v \n", req.Host)

	response += "Requested Resource: " + req.RequestURI + "\n"
	response += "Method: " + req.Method + "\n"
	response += "Protocol: " + req.Proto + "\n"
	response += "Content-Length: " + fmt.Sprint(req.ContentLength) + "\n\n"

	// TLS Information
	if req.TLS != nil {
		response += "Local Port: " + location + "\n"
		response += "TLS SNI: " + req.TLS.ServerName + "\n"
		response += "TLS Version: "
		for k, v := range tlsVersionsItoa {
			if req.TLS.Version == k {
				response += v + " \n"
			}
		}

		response += fmt.Sprint("TLS Cipher Suite: ")

		for _, cipher := range tls.CipherSuites() {
			if req.TLS.CipherSuite == cipher.ID {
				response += cipher.Name + "\n"
			}
		}

		for _, cipher := range tls.InsecureCipherSuites() {
			if req.TLS.CipherSuite == cipher.ID {
				response += cipher.Name + "\n"
			}
		}

		response += "TLS Negotiated Proto: " + req.TLS.NegotiatedProtocol + "\n\n"
	}

	response += "Headers: \n"
	for name, values := range req.Header {
		// Loop over all values for the name.
		for _, value := range values {
			response += fmt.Sprintf("[%v:%v] \n", name, value)
		}
	}

	response += "\nBody: \n"
	bodyBytes, err := ioutil.ReadAll(req.Body)

	if err != nil {
		log.Fatal(err)
	}

	response += string(bodyBytes) + "\n"

	return response
}

func Printlog(req *http.Request) {

	if debug {
		var output string = "\n" + dumpRequest(req)
		log.Println(output)
	}

	if req.Header.Get("CF-Connecting-IP") != "" {
		log.Println("Connection from: " + req.Header.Get("CF-Connecting-IP") + " via " + req.RemoteAddr + " to resource: " + req.RequestURI)
	} else {
		log.Println("Connection from: " + req.RemoteAddr + " to resource: " + req.RequestURI)
	}
}

func Request(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	var response string

	response += "Hello from a very basic Go HTTP(S) server implementation! ;)\n\n"
	response += dumpRequest(req)

	_, err := os.Stat("./public")

	if err != nil {
		log.Println("Please create the a folder ./public for serving files.")
	}

	path := "." + req.URL.Path
	if path == "./" {
		path = "./index.html"
		http.ServeFile(w, req, path)
	} else {
		fmt.Fprintf(w, "%v\n", response)
	}
}

func Ip(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	var response string

	response += req.RemoteAddr

	_, err := os.Stat("./public")

	if err != nil {
		log.Println("Please create the a folder ./public for serving files.")
	}

	path := "." + req.URL.Path
	if path == "./" {
		path = "./index.html"
		http.ServeFile(w, req, path)
	} else {
		fmt.Fprintf(w, "%v\n", response)
	}
}

func Longrequest(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	var response string

	response += "Hello from a very basic Go HTTP(S) server implementation! ;)\n\n"

	time.Sleep(30 * time.Second)

	response += dumpRequest(req)

	_, err := os.Stat("./public")

	if err != nil {
		log.Println("Please create the a folder ./public for serving files.")
	}

	path := "." + req.URL.Path
	if path == "./" {
		path = "./index.html"
		http.ServeFile(w, req, path)
	} else {
		fmt.Fprintf(w, "%v\n", response)
	}
}

func Cookie(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	// Set the expiration date one year in the future, create a cooke and set it.
	// https://go.dev/src/net/http/cookie.go
	queries := req.URL.Query()

	var cookies []http.Cookie

	if len(queries) != 0 {

		for k, values := range queries {
			for _, v := range values {
				expiration := time.Now().Add(365 * 24 * time.Hour)
				cookie := http.Cookie{} //{Name: "my_custom_cookie",Value:"abcd",Expires:expiration}
				cookie.Name = k
				cookie.Value = v
				cookie.Expires = expiration
				cookies = append(cookies, cookie)
				http.SetCookie(w, &cookie)
			}
		}
	} else {
		expiration := time.Now().Add(365 * 24 * time.Hour)
		cookie := http.Cookie{} //{Name: "my_custom_cookie",Value:"abcd",Expires:expiration}
		cookie.Name = "my_custom_cookie"
		cookie.Value = "abcd"
		cookie.Expires = expiration
		http.SetCookie(w, &cookie)
		cookies = append(cookies, cookie)
	}

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

	for _, cookie := range cookies {
		fmt.Fprintf(w, response, cookie.Name, cookie.Value, cookie.Path, cookie.Domain, cookie.Expires, cookie.MaxAge, cookie.Secure, cookie.HttpOnly, cookie.SameSite)
	}

}

func Readme(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	response, err := ioutil.ReadFile("./README.html")
	if err != nil {
		log.Printf("unable to read file: %v", err)
	}

	fmt.Fprintf(w, "%v\n", string(response))
}

func Response(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	response := "Setting the following response headers: \n"

	queries := req.URL.Query()

	for k, values := range queries {
		for _, v := range values {
			response += "\t[" + k + ", " + v + "]\n"
			w.Header().Add(k, v)
		}
	}

	fmt.Fprintf(w, "%v\n", string(response))
}

func Servefiles(w http.ResponseWriter, req *http.Request) {

	Printlog(req)

	_, err := os.Stat("./public")

	if err != nil {
		log.Println("Please create the a folder ./public for serving files.")
	}

	path := "." + req.URL.Path
	if path == "./" {
		path = "./public/index.html"
	}

	http.ServeFile(w, req, path)
}

func TokenValidate(w http.ResponseWriter, req *http.Request) {
	Printlog(req)

	var (
		ctx        = context.TODO()
		teamDomain = "https://sundquist.cloudflareaccess.com"
		certsURL   = fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

		// The Application Audience (AUD) tag for your application
		policyAUD = "d75b6b22beae665b3bf47507ef87f9cf4d1d1f193e271f624cc176439c58bd56"

		config = &oidc.Config{
			ClientID: policyAUD,
		}
		keySet   = oidc.NewRemoteKeySet(ctx, certsURL)
		verifier = oidc.NewVerifier(teamDomain, keySet, config)
	)

	var response string

	headers := req.Header

	// Make sure that the incoming request has our token header
	//  Could also look in the cookies for CF_AUTHORIZATION
	accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("No token on the request"))
		return
	}

	// Verify the access token
	ctx = req.Context()
	token, err := verifier.Verify(ctx, accessJWT)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
		return
	}

	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to parse token claims: %s", err.Error())))
		return
	}
	response += "Token claims:\n"
	for key, value := range claims {
		response += fmt.Sprintf("%s: %v\n", key, value)
	}

	// Make a new request to the identity endpoint
	client := &http.Client{}
	reqIdentity, err := http.NewRequest("GET", "https://access.gotestserver.com/cdn-cgi/access/get-identity", nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to create request: %s", err.Error())))
		return
	}
	reqIdentity.Header.Set("Cookie", fmt.Sprintf("CF_Authorization=%s", accessJWT))

	response += fmt.Sprintf("\n\n\n\nMaking request: %v", reqIdentity)

	respIdentity, err := client.Do(reqIdentity)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to get identity: %s", err.Error())))
		return
	}
	defer respIdentity.Body.Close()

	body, err := ioutil.ReadAll(respIdentity.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to read identity response: %s", err.Error())))
		return
	}

	// Copy the identity response to the original response
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, body, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to pretty print JSON: %s", err.Error())))
		return
	}

	response += "\n\n\n\n\n\n\n\n" + prettyJSON.String()
	fmt.Fprintf(w, "%v\n", response)
}

// 302; Redirect
func Threeohtwo(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.Header().Add("Location", req.URL.RawQuery)
	w.WriteHeader(302)
}

// 403; Forbidden
func Fourohthree(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(403)
}

// 404; File Not Found
func Fourohfour(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(404)
}

// 405; Server recognized request, but has rejected it
func Fourohfive(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(405)
}

// 500; Internal Server Error
func Fivehundred(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(500)
}

// 502;  Bad Gateway
func Fiveohtwo(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(502)
}

// 503; Service Temporarily Unavailable
func Fiveohthree(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(503)
}

// 504; Gateway Timeout Error
func Fiveohfour(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(504)
}

// 520; Cloudflare Defines invalid response codes as a 520:
func Fivetwenty(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	w.WriteHeader(69)
}

// 524; Cloudflare's timeout is 100 seconds so lets add just 1 second to the default
// If this becomes obnoxious, you could set the Timeout < 100 seconds
// https://api.cloudflare.com/#zone-settings-change-proxy-read-timeout-setting
func Fivetwentyfour(w http.ResponseWriter, req *http.Request) {
	Printlog(req)
	time.Sleep(101 * time.Second)
}

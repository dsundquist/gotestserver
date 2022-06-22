/*
Copyright © 2022 Dean Sundquist dean@sundquist.net

*/
package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var debug bool = false

var location string

var availableCiphers = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                      0x0005,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 0x000a,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  0x002f,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  0x0035,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               0x003c,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               0x009c,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               0x009d,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              0xc007,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          0xc009,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          0xc00a,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                0xc011,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           0xc012,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            0xc013,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            0xc014,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       0xc023,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         0xc027,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         0xc02f,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       0xc02b,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         0xc030,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       0xc02c,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   0xcca8,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
	"TLS_AES_128_GCM_SHA256":                        0x1301,
	"TLS_AES_256_GCM_SHA384":                        0x1302,
	"TLS_CHACHA20_POLY1305_SHA256":                  0x1303,
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
		tlsVersion, _ := cmd.Flags().GetString("tls")
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

		serve(port, https, mtls, cert, key, clientCert, tlsVersion, ciphers, http1)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func serve(port int, https bool, mtls bool, cert string, key string, clientCert string, tlsVersion string, ciphers string, http1 bool) {
	var err error

	http.HandleFunc("/", Request) // Default prints request headers
	http.HandleFunc("/cookie", Cookie)
	http.HandleFunc("/readme", Readme)
	http.HandleFunc("/request", Request)
	http.HandleFunc("/response", Response)
	http.HandleFunc("/public/", Servefiles)
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

	if mtls {

		// Credit to: https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
		// Need better erroring here, like you need server.crt, server.key AND client.crt
		// fmt.Print("Starting mTLS Server, will need ./server.crt, ./server.key, and ./client.crt...\n")

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

		var setTlsVersion uint16 = tls.VersionTLS10 // default would be 1.0

		if tlsVersion == "1.0" {
			fmt.Println("Using Minimum TLS version 1.0")
			setTlsVersion = tls.VersionTLS10
		} else if tlsVersion == "1.1" {
			fmt.Println("Using Minimum TLS version 1.1")
			setTlsVersion = tls.VersionTLS11
		} else if tlsVersion == "1.2" {
			fmt.Println("Using Minimum TLS version 1.2")
			setTlsVersion = tls.VersionTLS12
		} else if tlsVersion == "1.3" {
			fmt.Println("Using Minimum TLS version 1.3")
			setTlsVersion = tls.VersionTLS13
		} else {
			log.Fatal("Invalid Minimum TLS version, please choose from: 1.0, 1.1, 1.2, 1.3")
		}

		var tlsCiphers []uint16

		cipherSlice := strings.Split(ciphers, ",")

		for _, cipher := range cipherSlice {
			for available, value := range availableCiphers {
				if cipher == available {
					tlsCiphers = append(tlsCiphers, value)
				}
			}
		}

		if ciphers != "nil" && len(cipherSlice) > 0 {
			log.Fatalf(`Failed to match: %v to the available ciphers:
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA
	TLS_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA
	TLS_RSA_WITH_AES_256_CBC_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA256
	TLS_RSA_WITH_AES_128_GCM_SHA256
	TLS_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_RSA_WITH_RC4_128_SHA
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

	// TLS 1.3 cipher suites.
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_AES_128_GCM_SHA256
	TLS_AES_256_GCM_SHA384
	TLS_CHACHA20_POLY1305_SHA256`, ciphers)
		}

		fmt.Printf("Using ciphers (all available if blank): %v\n", tlsCiphers)

		tlsConfig := &tls.Config{
			CipherSuites:             tlsCiphers,
			MinVersion:               setTlsVersion,
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

func Printlog(req *http.Request) {

	if debug {

		var output string
		// Top level information
		output += "Debug Enabled, dropping entire request: \n\n"
		output += "Remote Addr: " + req.RemoteAddr + "\n"
		output += "Requested Resource: " + req.RequestURI + "\n"
		output += "Method: " + req.Method + "\n"
		output += "Protocol: " + req.Proto + "\n"
		output += "Content-Length: " + fmt.Sprint(req.ContentLength) + "\n"

		// TLS Information
		if req.TLS != nil {
			output += "Local Port: " + location + "\n"
			output += "TLS SNI: " + req.TLS.ServerName + "\n"
			output += "TLS Version: "
			if req.TLS.Version == 769 {
				output += "1.0 \n"
			} else if req.TLS.Version == 770 {
				output += "1.1 \n"
			} else if req.TLS.Version == 771 {
				output += "1.2 \n"
			} else if req.TLS.Version == 772 {
				output += "1.3 \n"
			} else {
				output += fmt.Sprint(req.TLS.Version) + "\n"
			}

			output += "TLS Cipher Suite: "

			for available, value := range availableCiphers {
				if req.TLS.CipherSuite == value {
					output += available + "\n"
				}
			}
			output += "TLS Negotiated Proto: " + req.TLS.NegotiatedProtocol + "\n"
		}

		// Print the headers, can this look better?
		output += "Headers: \n"
		for i, headers := range req.Header {
			output += "\t [" + i + ";"
			for j, v := range headers {
				// output += strconv.Itoa(j)
				if j == len(headers)-1 {
					output += v
				} else {
					output += v + ","
				}
			}
			output += "]\n"
		}

		//Output the body
		output += "Body: \n"
		bodyBytes, err := ioutil.ReadAll(req.Body)

		if err != nil {
			log.Fatal(err)
		}

		output += string(bodyBytes) + "\n"

		// Output the generated log
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

	response += "Hello from a very basic Go HTTPS server implementation! ;)\n\n"
	response += fmt.Sprintf("Remote Address: %v\n\n", req.RemoteAddr)
	response += fmt.Sprintf("Host: %v \n", req.Host)

	response += "Requested Resource: " + req.RequestURI + "\n"
	response += "Method: " + req.Method + "\n"
	response += "Protocol: " + req.Proto + "\n"
	response += "Content-Length: " + fmt.Sprint(req.ContentLength) + "\n\n"

	// TLS Information
	if req.TLS != nil {
		response += "TLS SNI: " + req.TLS.ServerName + "\n"
		response += "Local Port: " + location + "\n"
		response += "TLS Version: "
		if req.TLS.Version == 769 {
			response += "1.0 \n"
		} else if req.TLS.Version == 770 {
			response += "1.1 \n"
		} else if req.TLS.Version == 771 {
			response += "1.2 \n"
		} else if req.TLS.Version == 772 {
			response += "1.3 \n"
		} else {
			response += fmt.Sprint(req.TLS.Version) + "\n"
		}

		response += "TLS Cipher Suite: "

		for available, value := range availableCiphers {
			if req.TLS.CipherSuite == value {
				response += available + "\n"
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

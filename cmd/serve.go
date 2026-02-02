/*
Copyright © 2022 Dean Sundquist dean@sundquist.net
*/
package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
		listeningIP, _ := cmd.Flags().GetString("listening_ip")
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
			fmt.Printf("Starting HTTPS Server on: %v\n", listeningIP+":"+strconv.Itoa(port))
		} else {
			fmt.Printf("Starting HTTP Server on: %v\n", listeningIP+":"+strconv.Itoa(port))
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

		serve(listeningIP, port, https, mtls, cert, key, clientCert, tlsMinVersion, tlsMaxVersion, ciphers, http1)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

// Start the Webserver with all of the parameters obtained
func serve(listeningIP string, port int, https bool, mtls bool, cert string, key string, clientCert string, tlsMinVersion string, tlsMaxVersion string, ciphers string, http1 bool) {
	var err error

	http.HandleFunc("/", Request) // Default prints request headers
	http.HandleFunc("/upload", withUploadAuth(Upload))
	http.HandleFunc("/longerrequest", Longerrequest)
	http.HandleFunc("/cookie", Cookie)
	http.HandleFunc("/ip", Ip)
	http.HandleFunc("/readme", Readme)
	http.HandleFunc("/request", Request)
	http.HandleFunc("/longrequest", Longrequest)
	http.HandleFunc("/response", Response)
	http.HandleFunc("/public/", Servefiles)
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
	http.HandleFunc("/uploadtest", UploadTest)

	// Handle IPv6 and empty IPs correctly
	if strings.Contains(listeningIP, ":") && !strings.HasPrefix(listeningIP, "[") {
		location = "[" + listeningIP + "]:" + strconv.Itoa(port)
	} else if listeningIP == "" {
		location = ":" + strconv.Itoa(port)
	} else {
		location = listeningIP + ":" + strconv.Itoa(port)
	}

	if mtls { // mTLS server (doesn't utlize all parameters) https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

		// Create a CA certificate pool and add cert.pem to it
		var caCert []byte
		caCert, err = os.ReadFile(clientCert)
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

		response += "TLS Cipher Suite: "

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

	// Restore the Body so downstream handlers can still read it (important for multipart)
	req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

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

// getMaxSleepDuration returns maximum sleep allowed from env var or default (300s)
func getMaxSleepDuration() time.Duration {
	def := int64(300) // 300 seconds default
	v := os.Getenv("GOTESTSERVER_MAX_SLEEP_SECONDS")
	if v == "" {
		return time.Duration(def) * time.Second
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil || parsed < 0 {
		return time.Duration(def) * time.Second
	}
	return time.Duration(parsed) * time.Second
}

// Longerrequest sleeps for a duration specified in the X-Sleep-Duration header
// The header accepts Go duration strings (eg "5s", "100ms") or numeric seconds (eg "5" or "5.5").
func Longerrequest(w http.ResponseWriter, req *http.Request) {
	Printlog(req)

	header := req.Header.Get("X-Sleep-Duration")
	if header == "" {
		http.Error(w, "Missing X-Sleep-Duration header", http.StatusBadRequest)
		return
	}

	// Try to parse as a Go duration string first
	dur, err := time.ParseDuration(header)
	if err != nil {
		// try parse as float seconds
		sec, err2 := strconv.ParseFloat(header, 64)
		if err2 != nil {
			http.Error(w, "Invalid duration format; use Go duration (eg 5s) or seconds (eg 5)", http.StatusBadRequest)
			return
		}
		dur = time.Duration(sec * float64(time.Second))
	}

	if dur < 0 {
		http.Error(w, "Negative duration not allowed", http.StatusBadRequest)
		return
	}

	max := getMaxSleepDuration()
	if dur > max {
		http.Error(w, fmt.Sprintf("Requested sleep exceeds max allowed: %v", max), http.StatusBadRequest)
		return
	}

	time.Sleep(dur)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Slept for %v\n", dur)
}

// getUploadSecret returns the upload secret from environment or a default.
func getUploadSecret() string {
	s := os.Getenv("GOTESTSERVER_UPLOAD_SECRET")
	if s == "" {
		s = "changeme"
	}
	return s
}

// getMaxUploadSize returns the maximum allowed upload size in bytes from env or default (1GB).
func getMaxUploadSize() int64 {
	def := int64(1 << 30) // 1GB
	v := os.Getenv("GOTESTSERVER_MAX_UPLOAD_BYTES")
	if v == "" {
		return def
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil || parsed <= 0 {
		return def
	}
	return parsed
}

// withUploadAuth is middleware that checks for the X-Upload-Secret header.
func withUploadAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		secret := getUploadSecret()
		header := req.Header.Get("X-Upload-Secret")
		if header == "" {
			http.Error(w, "Missing upload secret header", http.StatusUnauthorized)
			return
		}
		if header != secret {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, req)
	}
}

// Upload handles multipart file uploads and streams files to ./uploads
func Upload(w http.ResponseWriter, req *http.Request) {
	Printlog(req)

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	maxSize := getMaxUploadSize()
	req.Body = http.MaxBytesReader(w, req.Body, maxSize)

	mr, err := req.MultipartReader()
	if err != nil {
		http.Error(w, "Invalid multipart request", http.StatusBadRequest)
		return
	}

	var saved []string

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading multipart data", http.StatusInternalServerError)
			return
		}

		if part.FileName() == "" {
			// skip non-file fields
			continue
		}

		fname := filepath.Base(part.FileName())
		if fname == "" {
			continue
		}

		err = os.MkdirAll("./uploads", 0755)
		if err != nil {
			http.Error(w, "Unable to create uploads directory", http.StatusInternalServerError)
			return
		}

		outPath := filepath.Join("uploads", fname)
		out, err := os.Create(outPath)
		if err != nil {
			http.Error(w, "Unable to create file", http.StatusInternalServerError)
			return
		}

		_, err = io.Copy(out, part)
		out.Close()
		part.Close()
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}

		saved = append(saved, outPath)
	}

	if len(saved) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Saved: %v\n", strings.Join(saved, ","))
}

// UploadTest handles file uploads, discards the content, and returns an HTML page with file details
func UploadTest(w http.ResponseWriter, req *http.Request) {
	Printlog(req)

	// If GET request, show the upload form
	if req.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>File Upload Test</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 30px; }
        .upload-form { border: 2px dashed #ccc; padding: 40px; text-align: center; border-radius: 8px; transition: border-color 0.3s; }
        .upload-form:hover { border-color: #007bff; }
        input[type="file"] { margin: 20px 0; }
        button { background: #007bff; color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .note { color: #666; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 File Upload Test</h1>
        <form class="upload-form" action="/uploadtest" method="POST" enctype="multipart/form-data">
            <p>Select a file to upload (it will be discarded after processing)</p>
            <input type="file" name="file" multiple>
            <br><br>
            <button type="submit">Upload File(s)</button>
        </form>
        <p class="note">Note: Files are not saved to disk. This endpoint only reports file metadata.</p>
    </div>
</body>
</html>`)
		return
	}

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	maxSize := getMaxUploadSize()
	req.Body = http.MaxBytesReader(w, req.Body, maxSize)

	mr, err := req.MultipartReader()
	if err != nil {
		http.Error(w, "Invalid multipart request", http.StatusBadRequest)
		return
	}

	type fileInfo struct {
		Filename    string
		Size        int64
		ContentType string
	}
	var files []fileInfo
	var totalSize int64

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading multipart data", http.StatusInternalServerError)
			return
		}

		if part.FileName() == "" {
			part.Close()
			continue
		}

		fname := filepath.Base(part.FileName())
		contentType := part.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		// Read and discard the file content, counting bytes
		n, err := io.Copy(io.Discard, part)
		part.Close()
		if err != nil {
			http.Error(w, "Error reading file data", http.StatusInternalServerError)
			return
		}

		files = append(files, fileInfo{
			Filename:    fname,
			Size:        n,
			ContentType: contentType,
		})
		totalSize += n
	}

	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	// Generate HTML response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>Upload Complete</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #28a745; margin-bottom: 30px; }
        .summary { background: #e8f5e9; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .summary h2 { margin: 0 0 10px 0; color: #2e7d32; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        .size { font-family: monospace; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Upload Complete!</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Files Processed:</strong> `)
	fmt.Fprintf(w, "%d", len(files))
	fmt.Fprint(w, `</p>
            <p><strong>Total Size:</strong> <span class="size">`)
	fmt.Fprintf(w, "%s", formatBytes(totalSize))
	fmt.Fprint(w, `</span></p>
            <p><strong>Status:</strong> All files discarded (not saved to disk)</p>
        </div>
        <h2>File Details</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Filename</th>
                <th>Size</th>
                <th>Content-Type</th>
            </tr>`)

	for i, f := range files {
		fmt.Fprintf(w, `
            <tr>
                <td>%d</td>
                <td>%s</td>
                <td class="size">%s</td>
                <td>%s</td>
            </tr>`, i+1, f.Filename, formatBytes(f.Size), f.ContentType)
	}

	fmt.Fprint(w, `
        </table>
        <p style="margin-top: 30px;"><a href="/uploadtest">← Upload another file</a></p>
    </div>
</body>
</html>`)
}

// formatBytes converts bytes to a human-readable string
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
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

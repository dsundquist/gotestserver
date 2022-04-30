package main

import (
	"fmt"
	"log"
	"net/http"
)


func main() {

  log.Println("\nStarting Server...\n")

  http.HandleFunc("/", PrintHeaders) // Default prints request headers

  log.Fatal(http.ListenAndServe(":8080", nil))
}

func PrintHeaders(w http.ResponseWriter, req *http.Request) {

  var response string

  response += "The 522 Server\n\n"

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



package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)


func main() {

  fmt.Println("\nStarting Server...\n")

  http.HandleFunc("/", PrintHeaders)
  http.HandleFunc("/404", Fourohfour)
  http.HandleFunc("/520", Fivetwenty)
  http.HandleFunc("/524", Fivetwentyfour)

  log.Fatal(http.ListenAndServeTLS(":443", "public.crt", "key.crt", nil))

}

func PrintHeaders(w http.ResponseWriter, req *http.Request) {

  var response string

  response += "Hello from a very basic Go HTTPS server implementation! ;)\n\n"

  response += fmt.Sprintf("Remote Address: %v\n\n", req.RemoteAddr)

   response += fmt.Sprintf("Host: %v \n", req.Host)

  for name, values := range req.Header {
   // Loop over all values for the name.
    for _, value := range values {
      response += fmt.Sprintf("Header: %v Value: %v \n", name, value)
    }
  }

fmt.Fprintf(w, "%v\n", response)


}

func Fourohfour(w http.ResponseWriter, req *http.Request) {
 w.WriteHeader(404)
}


func Fivetwenty(w http.ResponseWriter, req *http.Request) {

  fmt.Fprint(w, "This should have returned a 520")

}

func Fivetwentyfour(w http.ResponseWriter, req *http.Request) {


  time.Sleep(91 * time.Second)
  fmt.Fprint(w, "This should have returned a 524")

}

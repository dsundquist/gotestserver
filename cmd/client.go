package cmd

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "And HTTP(s) client",
	Long:  `Used to create to the Server instance`,
	Run: func(cmd *cobra.Command, args []string) {
		location, _ := cmd.Flags().GetString("location")
		insecure, _ := cmd.Flags().GetBool("insecure")
		client(location, insecure)
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)
}

func client(location string, insecure bool) {

	//Ignore bad / self signed certificates.
	if insecure {
		fmt.Println("Ignoring selfsigned / bad certificates")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// For MTLS we're going to need to move away form this http.get to client.get
	// I'm following this at this time: https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

	r, err := http.Get(location)
	if err != nil {
		log.Fatal(err)
	}

	// Read the response body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response body to stdout
	fmt.Printf("%s\n", body)
}

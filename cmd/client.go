package cmd

import (
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
		client(location)
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)
}

func client(location string) {

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

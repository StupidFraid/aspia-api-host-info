package main

import (
	"fmt"
	"log"
	"os"

	"aspia_rest_api/models"
	"aspia_rest_api/pkg/aspia"
)

func main() {
	config, err := models.LoadConfig("config.ini")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Connecting to router at %s:%d as %s...\n", config.RouterHost, config.RouterPort, config.RouterUsername)

	client := aspia.NewClient()
	address := fmt.Sprintf("%s:%d", config.RouterHost, config.RouterPort)

	// Try ConnectAdmin first as it seems to be the intended use for the service
	err = client.ConnectAdmin(address, config.RouterUsername, config.RouterPassword)
	if err != nil {
		fmt.Printf("❌ ConnectAdmin failed: %v\n", err)

		// Try regular Connect
		fmt.Println("Retrying with regular Connect...")
		err = client.Connect(address, config.RouterUsername, config.RouterPassword)
		if err != nil {
			fmt.Printf("❌ Connect failed: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("✅ Authentication successful!")

	// Try to get hosts to verify session is working
	hosts, err := client.GetHosts()
	if err != nil {
		fmt.Printf("⚠️ Authentication worked, but GetHosts failed: %v\n", err)
	} else {
		fmt.Printf("✅ Successfully retrieved %d hosts\n", len(hosts))
		for _, h := range hosts {
			fmt.Printf(" - %s (ID: %d, IP: %s)\n", h.ComputerName, h.SessionId, h.IpAddress)
		}
	}

	client.Disconnect()
}

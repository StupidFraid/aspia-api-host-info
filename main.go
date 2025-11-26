package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"aspia_rest_api/handlers"
	"aspia_rest_api/models"
	"aspia_rest_api/pkg/aspia"
	"aspia_rest_api/pkg/aspia/crypto"

	"github.com/gorilla/mux"
)

func main() {
	// Initialize router
	r := mux.NewRouter()

	// Initialize service
	config, err := models.LoadConfig("./config.ini")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize debug logging
	aspia.SetDebug(config.Debug)
	crypto.SetDebug(config.Debug)

	service := handlers.NewAspiaService(config)

	// Define routes
	r.HandleFunc("/hosts", service.GetHosts).Methods("GET")
	r.HandleFunc("/hosts/{hostId}/config", service.GetHostConfig).Methods("GET")
	r.HandleFunc("/health", healthCheck).Methods("GET")

	// Start server
	port := ":8080"
	fmt.Printf("Starting Aspia REST API server on %s\n", port)
	log.Fatal(http.ListenAndServe(port, r))
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

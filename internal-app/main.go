package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	hostname, _ := os.Hostname()
	port := "80"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Internal App — accessible only via SSH tunnel\n")
		fmt.Fprintf(w, "Hostname: %s\n", hostname)
		fmt.Fprintf(w, "Time: %s\n", time.Now().Format(time.RFC3339))
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok")
	})

	log.Printf("Internal app starting on :%s (hostname: %s)", port, hostname)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
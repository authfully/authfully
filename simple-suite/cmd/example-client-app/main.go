package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Hard code to use this callback path for redirect uri
const callbackPath = "/callback"

//go:embed templates/index.tmpl.html
var indexHTML string

//go:embed assets
var assetsFS embed.FS

func parseAddress(portStr, defaultPort string) (string, error) {
	if portStr == "" {
		portStr = defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("port number out of range: %d", port)
	}
	return ":" + strconv.Itoa(port), nil
}

func deriveRedirectUri(r *http.Request, path string) (redirectUri *url.URL) {
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	redirectUri = &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   path,
	}
	return
}

func main() {
	// Load if .env exists
	if _, err := os.Stat(".env"); err == nil {
		log.Println("Loading .env file")
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}

	// Check all os.Getenv variables
	if os.Getenv("CLIENT_ID") == "" {
		log.Fatal("CLIENT_ID is not set")
	}
	if os.Getenv("CLIENT_SECRET") == "" {
		log.Fatal("CLIENT_SECRET is not set")
	}
	if os.Getenv("AUTH_ENDPOINT_URL") == "" {
		log.Fatal("AUTH_ENDPOINT_URL is not set")
	}
	defaultPort := "8080"
	if os.Getenv("PORT") == "" {
		log.Printf("PORT is not set, fallback to default %s", defaultPort)
	}

	// Parse the port number from the environment variable
	addr, err := parseAddress(os.Getenv("PORT"), defaultPort)
	if err != nil {
		log.Fatalf("Invalid port number: %v", err)
	}

	// Other variable setups
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	_ = clientSecret // placeholder for future use
	authEndpoint := os.Getenv("AUTH_ENDPOINT_URL")

	// HTML template to use
	indexTemplate := template.Must(template.New("index").Parse(indexHTML))

	// Primary landing page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirectUri := deriveRedirectUri(r, callbackPath)
		log.Printf("Redirect URI: %s", redirectUri.String())

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		indexTemplate.Execute(w, struct {
			AuthEndpoint string
			ClientID     string
			RedirectURI  string
			Scope        string
			State        string
			ResponseType string
		}{
			AuthEndpoint: authEndpoint,
			ClientID:     clientID,
			RedirectURI:  redirectUri.String(),
			Scope:        "openid profile email",
			State:        "random_state_string",
			ResponseType: "code",
		})
	})

	// Callback handler
	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		// Handle the callback from the authorization server
		// This is where you would exchange the authorization code for an access token
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Callback received!"))
	})

	// Serve static assets
	http.Handle("/assets/", http.FileServer(http.FS(assetsFS)))

	// Server the default handler
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	defer listener.Close()
	log.Printf("Listening on %s", addr)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
	log.Printf("Server stopped")
}

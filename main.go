package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	appName = "webhook-listener"
	version = "1.0.0"
)

type GitHubPayload struct {
	Action      string      `json:"action"`
	Number      int         `json:"number"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  Repository  `json:"repository"`
	Ref         string      `json:"ref"`
	Before      string      `json:"before"`
	After       string      `json:"after"`
}

type PullRequest struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	Head    Branch `json:"head"`
	Base    Branch `json:"base"`
	HTMLURL string `json:"html_url"`
}

type Branch struct {
	Ref  string     `json:"ref"`
	SHA  string     `json:"sha"`
	Repo Repository `json:"repo"`
}

type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
}

type WebhookServer struct {
	port   string
	secret string
}

func NewWebhookServer(port, secret string) *WebhookServer {
	return &WebhookServer{
		port:   port,
		secret: secret,
	}
}

func (ws *WebhookServer) validateSignature(payload []byte, signature string) bool {
	if ws.secret == "" {
		return true
	}

	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	expectedMAC := hmac.New(sha256.New, []byte(ws.secret))
	expectedMAC.Write(payload)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func (ws *WebhookServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("X-Hub-Signature-256")
	if !ws.validateSignature(body, signature) {
		log.Printf("Invalid signature for webhook request")
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		log.Printf("No GitHub event type in headers")
		http.Error(w, "No event type", http.StatusBadRequest)
		return
	}

	var payload GitHubPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error parsing JSON payload: %v", err)
		http.Error(w, "Error parsing JSON", http.StatusBadRequest)
		return
	}

	ws.handleGitHubEvent(eventType, &payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (ws *WebhookServer) handleGitHubEvent(eventType string, payload *GitHubPayload) {
	repo := payload.Repository.FullName
	timestamp := time.Now().Format("15:04:05")

	switch eventType {
	case "pull_request":
		action := payload.Action
		pr := payload.PullRequest

		fmt.Printf("[%s] 🔀 PR #%d %s: %s\n", timestamp, pr.Number, action, pr.Title)
		fmt.Printf("         Repository: %s\n", repo)
		fmt.Printf("         Branch: %s → %s\n", pr.Head.Ref, pr.Base.Ref)
		fmt.Printf("         URL: %s\n", pr.HTMLURL)
		fmt.Println()

		if action == "opened" || action == "synchronize" {
			ws.handleRepositoryEvent(repo, pr.Head.Ref, payload.Repository.CloneURL)
		}

	case "push":
		ref := payload.Ref
		branch := strings.TrimPrefix(ref, "refs/heads/")

		if !strings.HasPrefix(ref, "refs/heads/") {
			return
		}

		fmt.Printf("[%s] 📤 Push to %s\n", timestamp, repo)
		fmt.Printf("         Branch: %s\n", branch)
		fmt.Printf("         Commits: %s...%s\n", payload.Before[:8], payload.After[:8])
		fmt.Printf("         [📝] Repo: %s, Branch: %s\n", repo, branch)
		fmt.Println()

	case "ping":
		fmt.Printf("[%s] 🏓 Webhook ping from %s\n", timestamp, repo)
		fmt.Println("         Webhook successfully configured!")
		fmt.Println()

	default:
		fmt.Printf("[%s] 📋 GitHub event: %s from %s\n", timestamp, eventType, repo)
		if payload.Action != "" {
			fmt.Printf("         Action: %s\n", payload.Action)
		}
		fmt.Println()
	}
}

func (ws *WebhookServer) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "webhook-listener",
		"version": version,
	})
}

func (ws *WebhookServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/webhook", ws.handleWebhook)
	mux.HandleFunc("/health", ws.healthCheck)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Webhook Listener v%s\nEndpoints:\n  POST /webhook - GitHub webhooks\n  GET /health - Health check\n", version)
	})

	server := &http.Server{
		Addr:    ":" + ws.port,
		Handler: mux,
	}

	fmt.Printf("🚀 Webhook Listener v%s starting on port %s\n", version, ws.port)
	fmt.Println("📋 Endpoints:")
	fmt.Printf("    POST http://localhost:%s/webhook - GitHub webhooks\n", ws.port)
	fmt.Printf("    GET  http://localhost:%s/health  - Health check\n", ws.port)
	fmt.Println()
	fmt.Println("🔗 Configure GitHub webhook URL: http://your-domain.com/webhook")
	fmt.Println("📝 Listening for GitHub events...")
	fmt.Println()

	return server.ListenAndServe()
}

func printUsage() {
	fmt.Printf(`%s v%s - GitHub Webhook Listener

Usage:
  %s <command> [options]

Commands:
  listen [--port PORT] [--secret SECRET]  Start webhook server for GitHub events
  help                                    Show this help message
  version                                 Show version information

Options:
  --port PORT          Webhook server port (default: 3000)
  --secret SECRET      GitHub webhook secret for validation

Examples:
  %s listen
  %s listen --port 3000 --secret mysecret

`, appName, version, appName, appName, appName)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "listen":
		port := "3000"
		secret := ""

		args := os.Args[2:]
		for i, arg := range args {
			switch arg {
			case "--port", "-p":
				if i+1 < len(args) {
					port = args[i+1]
				}
			case "--secret", "-s":
				if i+1 < len(args) {
					secret = args[i+1]
				}
			}
		}

		server := NewWebhookServer(port, secret)
		if err := server.Start(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "help", "-h", "--help":
		printUsage()

	case "version", "-v", "--version":
		fmt.Printf("%s v%s\n", appName, version)

	default:
		fmt.Printf("Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(1)
	}
}

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	_ "github.com/mattn/go-sqlite3"
)

const (
	appName = "webhook-listener"
	version = "1.0.0"
)

type GitHubPayload struct {
	Action     string     `json:"action"`
	Number     int        `json:"number"`
	Repository Repository `json:"repository"`
	Ref        string     `json:"ref"`
	Before     string     `json:"before"`
	After      string     `json:"after"`
}

type WorkflowRunPayload struct {
	Action       string       `json:"action"`
	WorkflowRun  WorkflowRun  `json:"workflow_run"`
	Repository   Repository   `json:"repository"`
	Sender       User         `json:"sender"`
	Installation Installation `json:"installation"`
}

type WorkflowRun struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	NodeID       string     `json:"node_id"`
	HeadBranch   string     `json:"head_branch"`
	HeadSHA      string     `json:"head_sha"`
	Path         string     `json:"path"`
	RunNumber    int        `json:"run_number"`
	Event        string     `json:"event"`
	Status       string     `json:"status"`
	Conclusion   string     `json:"conclusion"`
	WorkflowID   int64      `json:"workflow_id"`
	URL          string     `json:"url"`
	HTMLURL      string     `json:"html_url"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	RunAttempt   int        `json:"run_attempt"`
	JobsURL      string     `json:"jobs_url"`
	LogsURL      string     `json:"logs_url"`
	ArtifactsURL string     `json:"artifacts_url"`
	HeadCommit   HeadCommit `json:"head_commit"`
}

type HeadCommit struct {
	ID        string    `json:"id"`
	TreeID    string    `json:"tree_id"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Author    Author    `json:"author"`
	Committer Author    `json:"committer"`
}

type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type User struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	NodeID    string `json:"node_id"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Type      string `json:"type"`
}

type Installation struct {
	ID     int64  `json:"id"`
	NodeID string `json:"node_id"`
}

type Artifact struct {
	ID                 int64     `json:"id"`
	NodeID             string    `json:"node_id"`
	Name               string    `json:"name"`
	SizeInBytes        int64     `json:"size_in_bytes"`
	URL                string    `json:"url"`
	ArchiveDownloadURL string    `json:"archive_download_url"`
	Expired            bool      `json:"expired"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type ArtifactsResponse struct {
	TotalCount int        `json:"total_count"`
	Artifacts  []Artifact `json:"artifacts"`
}

type GitHubAppClaims struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
	jwt.RegisteredClaims
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
	port    string
	secret  string
	db      *sql.DB
	dotPath string
}

type Deployment struct {
	ID          int
	Repo        *string
	Branch      *string
	Sitename    string
	Description *string
	Created     time.Time
}

type RepositoryConfig struct {
	ID            int    `json:"id"`
	Repo          string `json:"repo"`
	BuildMode     string `json:"build_mode"`
	WpcliCommands string `json:"wpcli_commands"`
}

type DockerBuildConfig struct {
	RepositoryConfig
	CustomScript string   `json:"custom_script"`
	ZipPaths     []string `json:"zip_paths"`
}

type GitHubWorkflowConfig struct {
	RepositoryConfig
	WorkflowName  *string  `json:"workflow_name"`
	ArtifactNames []string `json:"artifact_names"`
}

func NewWebhookServer(port, secret string) *WebhookServer {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to get home directory: %v", err)
		return nil
	}

	dotPath := filepath.Join(homeDir, ".wpp-deployer")

	dbLocation := filepath.Join(dotPath, "deployments.db")
	db, err := sql.Open("sqlite3", dbLocation)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	ws := &WebhookServer{
		port:    port,
		secret:  secret,
		db:      db,
		dotPath: dotPath,
	}

	if err := ws.initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	return ws
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

	err = ws.handleGitHubEvent(eventType, body)
	if err != nil {
		http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (ws *WebhookServer) handleGitHubEvent(eventType string, body []byte) error {
	timestamp := time.Now().Format("15:04:05")

	var payload GitHubPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error parsing JSON payload: %v", err)
		return fmt.Errorf("Error parsing JSON")
	}

	repo := payload.Repository.FullName

	var repoConfig RepositoryConfig

	err := ws.db.QueryRow(`
		SELECT id, repo, build_mode, wpcli_commands 
		FROM repositories 
		WHERE repo = ?`, strings.ToLower(repo)).Scan(
		&repoConfig.ID, &repoConfig.Repo, &repoConfig.BuildMode, &repoConfig.WpcliCommands)

	if err != nil {
		return fmt.Errorf("Repository %s is not configured: %v", repo, err)
	}

	switch eventType {
	case "push":
		ref := payload.Ref
		branch := strings.TrimPrefix(ref, "refs/heads/")

		if !strings.HasPrefix(ref, "refs/heads/") {
			return nil
		}

		fmt.Printf("[%s] 📤 Push to %s\n", timestamp, repo)
		fmt.Printf("         Branch: %s\n", branch)
		fmt.Printf("         Commits: %s...%s\n", payload.Before[:8], payload.After[:8])
		fmt.Printf("         [📝] Repo: %s, Branch: %s\n", repo, branch)
		fmt.Println()

		if repoConfig.BuildMode == "docker" {
			go func() {
				log.Printf("Starting Docker build and deploy process for %s:%s", repo, branch)
				if err := ws.deployPlugins(&repoConfig, branch, nil, ws.buildWithDocker); err != nil {
					log.Printf("Error processing Docker deployment for %s:%s - %v", repo, branch, err)
				}
			}()
		} else {
			log.Printf("Repository not configured to use docker build, ignoring push event.")
		}

	case "workflow_run":
		var payload WorkflowRunPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			log.Printf("Error parsing workflow_run payload: %v", err)
			return fmt.Errorf("Error parsing JSON")
		}

		run := payload.WorkflowRun

		if payload.Action == "completed" && run.Conclusion == "success" {
			fmt.Printf("[%s] ⚙️  Workflow Run: %s\n", timestamp, run.Name)
			fmt.Printf("         Repository: %s\n", repo)
			fmt.Printf("         Branch: %s\n", run.HeadBranch)
			fmt.Printf("         Event: %s\n", run.Event)
			fmt.Printf("         URL: %s\n", run.HTMLURL)

			if repoConfig.BuildMode == "github_workflow" {
				go func() {
					log.Printf("Starting deploy process github workflow artifacts for %s:%s", repo, run.HeadBranch)
					if err := ws.deployPlugins(&repoConfig, run.HeadBranch, &payload, ws.retrieveWorkflowArtifacts); err != nil {
						log.Printf("Error processing github workflow deployment for %s:%s - %v", repo, run.HeadBranch, err)
					}
				}()
			} else {
				log.Printf("Repository not configured to use github workflow artifacts, ignoring github workflow success event.")
			}
		}

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

	return nil
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

Environment Variables (for GitHub App authentication):
  GITHUB_APP_ID                GitHub App ID
  GITHUB_APP_PRIVATE_KEY_PATH  Path to GitHub App private key file
  GITHUB_APP_PRIVATE_KEY       GitHub App private key content (alternative to path)

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

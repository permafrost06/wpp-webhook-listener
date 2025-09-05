package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

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
	db     *sql.DB
}

type Deployment struct {
	ID       int
	Repo     string
	Branch   string
	Sitename string
	Created  time.Time
}

func NewWebhookServer(port, secret string) *WebhookServer {
	homeDir, err := os.UserHomeDir()
	dbLocation := filepath.Join(homeDir, ".wpp-deployer", "deployments.db")
	db, err := sql.Open("sqlite3", dbLocation)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	ws := &WebhookServer{
		port:   port,
		secret: secret,
		db:     db,
	}

	if err := ws.initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	return ws
}

func (ws *WebhookServer) initDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS deployments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repo TEXT NOT NULL,
		branch TEXT NOT NULL,
		sitename TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(repo, branch)
	);`

	_, err := ws.db.Exec(query)
	return err
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

		ws.buildPluginAndDeploySite(repo, branch)

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

func (ws *WebhookServer) buildPluginAndDeploySite(repo string, branch string) {
	configuredRepos := []string{
		"dotcamp/tableberg",
		"dotcamp/ultimate-blocks",
	}

	if !slices.Contains(configuredRepos, strings.ToLower(repo)) {
		return
	}

	go func() {
		log.Printf("Starting build and deploy process for %s:%s", repo, branch)

		if err := ws.processRepoDeployment(repo, branch); err != nil {
			log.Printf("Error processing deployment for %s:%s - %v", repo, branch, err)
		}
	}()
}

func (ws *WebhookServer) deployNewSite(repo string, branch string) (Deployment, error) {
	var deployment Deployment

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = chars[b[i]%byte(len(chars))]
	}
	sitename := string(b)

	_, err := ws.db.Exec(
		"INSERT INTO deployments (repo, branch, sitename) VALUES (?, ?, ?)",
		repo, branch, sitename,
	)
	if err != nil {
		return Deployment{}, fmt.Errorf("failed to insert deployment: %v", err)
	}

	deployment.Repo = repo
	deployment.Branch = branch
	deployment.Sitename = sitename
	deployment.Created = time.Now()

	return deployment, nil
}

func (ws *WebhookServer) processRepoDeployment(repo, branch string) error {
	var deployment Deployment

	err := ws.db.QueryRow(
		"SELECT id, repo, branch, sitename, created_at FROM deployments WHERE repo = ? AND branch = ?",
		repo, branch,
	).Scan(&deployment.ID, &deployment.Repo, &deployment.Branch, &deployment.Sitename, &deployment.Created)

	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to query deployment: %v", err)
	}

	if err == sql.ErrNoRows {
		deployment, err = ws.deployNewSite(repo, branch)
		if err != nil {
			return fmt.Errorf("failed to deploy new site: %v", err)
		}
	}

	log.Printf("Using site: %s for %s:%s", deployment.Sitename, repo, branch)

	output, err := exec.Command("wpp-deployer", "list").Output()
	if err != nil {
		return fmt.Errorf("failed to list deployments: %v", err)
	}

	if !strings.Contains(string(output), deployment.Sitename) {
		log.Printf("Deploying new site: %s", deployment.Sitename)
		if err := exec.Command("wpp-deployer", "deploy", deployment.Sitename).Run(); err != nil {
			return fmt.Errorf("failed to deploy site %s: %v", deployment.Sitename, err)
		}

		log.Printf("Successfully deployed site: %s", deployment.Sitename)
	} else {
		log.Printf("Site %s already exists", deployment.Sitename)
	}

	log.Printf("Building %s:%s with Docker", repo, branch)

	repoURL := fmt.Sprintf("https://github.com/%s", repo)

	var zipPath string
	if strings.Contains(repo, "ultimate-blocks") {
		zipPath = "packages/ultimate-blocks/zip/ultimate-blocks.zip"
	} else if strings.Contains(repo, "tableberg") {
		zipPath = "packages/tableberg/tableberg.zip"
	} else {
		return fmt.Errorf("unknown repo type: %s", repo)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	absOutputDir, err := filepath.Abs(filepath.Join(homeDir, ".wpp-deployer", "docker-build-output", deployment.Sitename))
	if err != nil {
		return fmt.Errorf("failed to get absolute path for output dir: %v", err)
	}

	absStoreDir, err := filepath.Abs(filepath.Join(homeDir, ".wpp-deployer", "pnpm-store"))
	if err != nil {
		return fmt.Errorf("failed to get absolute path for pnpm store dir: %v", err)
	}

	dockerArgs := []string{
		"run", "-v", fmt.Sprintf("%s:/output", absOutputDir),
		"-v", fmt.Sprintf("%s:/pnpm/store", absStoreDir),
		"project-builder", repoURL, branch, zipPath,
	}

	output, err = exec.Command("docker", dockerArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker build failed: %v, output: %s", err, string(output))
	}

	builtZipPath := filepath.Join(absOutputDir, filepath.Base(zipPath))
	if _, err := os.Stat(builtZipPath); os.IsNotExist(err) {
		return fmt.Errorf("expected zip file not found: %s", builtZipPath)
	}

	log.Printf("Successfully built plugin: %s", builtZipPath)

	log.Printf("Installing plugin %s on site %s", zipPath, deployment.Sitename)

	siteDir := filepath.Join(homeDir, ".wpp-deployer", fmt.Sprintf("wordpress-%s", deployment.Sitename))

	cmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "run", "-T", "--rm", "wpcli",
		"plugin", "install", fmt.Sprintf("/zips/%s", filepath.Base(zipPath)), "--activate", "--force")
	cmd.Dir = siteDir

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("plugin installation failed: %v, output: %s", err, string(output))
	}

	log.Printf("Successfully installed plugin on site %s", deployment.Sitename)

	log.Printf("Successfully completed build and deploy for %s:%s on site %s", repo, branch, deployment.Sitename)
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

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
	"os/exec"
	"path/filepath"
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
	port      string
	secret    string
	configMgr *ConfigManager
	deployer  *DeployerClient
}

func NewWebhookServer(port, secret string) *WebhookServer {
	workDir := filepath.Join(os.Getenv("HOME"), ".webhook-listener")

	return &WebhookServer{
		port:      port,
		secret:    secret,
		configMgr: NewConfigManager(workDir),
		deployer:  NewDeployerClient(),
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
		fmt.Println()

		ws.handleRepositoryEvent(repo, branch, payload.Repository.CloneURL)

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

func (ws *WebhookServer) handleRepositoryEvent(repoFullName, branch, cloneURL string) {
	config, err := ws.configMgr.GetRepoConfig(repoFullName)
	if err != nil {
		fmt.Printf("         [!] Repository %s not configured for deployment: %v\n", repoFullName, err)
		return
	}

	fmt.Printf("         [+] Repository configured for deployment\n")
	fmt.Printf("         [+] Script: %s\n", config.Script)

	if err := ws.processRepository(repoFullName, branch, cloneURL, config); err != nil {
		fmt.Printf("         [!] Processing failed: %v\n", err)
		return
	}

	fmt.Printf("         [✔] Repository processing completed successfully!\n")
	fmt.Println()
}

func (ws *WebhookServer) processRepository(repoFullName, branch, cloneURL string, config *RepoConfig) error {
	workDir := ws.configMgr.GetWorkDir()
	repoDir := filepath.Join(workDir, "repos", repoFullName)

	if err := os.MkdirAll(filepath.Dir(repoDir), 0755); err != nil {
		return fmt.Errorf("failed to create repos directory: %w", err)
	}

	if err := ws.cloneOrUpdateRepo(repoDir, cloneURL, branch); err != nil {
		return fmt.Errorf("failed to clone/update repository: %w", err)
	}

	if err := ws.runBuildScript(repoDir, config.Script, repoFullName, branch); err != nil {
		return fmt.Errorf("failed to run build script: %w", err)
	}

	siteName, err := ws.deployer.DeployWithPlugin(repoDir, repoFullName, branch)
	if err != nil {
		return fmt.Errorf("failed to deploy with wpp-deployer: %w", err)
	}

	fmt.Printf("         [+] Site deployed: %s.nshlog.com\n", siteName)
	return nil
}

func (ws *WebhookServer) cloneOrUpdateRepo(repoDir, cloneURL, branch string) error {
	fmt.Printf("         [+] Updating repository...\n")

	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		fmt.Printf("         [+] Cloning repository...\n")
		cmd := exec.Command("git", "clone", "--depth", "1", "--branch", branch, cloneURL, repoDir)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone failed: %w", err)
		}
	} else {
		fmt.Printf("         [+] Pulling latest changes...\n")

		cmd := exec.Command("git", "reset", "--hard")
		cmd.Dir = repoDir
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git reset failed: %w", err)
		}

		cmd = exec.Command("git", "checkout", branch)
		cmd.Dir = repoDir
		if err := cmd.Run(); err != nil {
			cmd = exec.Command("git", "checkout", "-b", branch, "origin/"+branch)
			cmd.Dir = repoDir
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("git checkout failed: %w", err)
			}
		}

		cmd = exec.Command("git", "pull", "origin", branch)
		cmd.Dir = repoDir
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git pull failed: %w", err)
		}
	}

	return nil
}

func (ws *WebhookServer) runBuildScript(repoDir, script, repoFullName, branch string) error {
	fmt.Printf("         [+] Running build script: %s\n", script)

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = repoDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("REPO_NAME=%s", repoFullName),
		fmt.Sprintf("BRANCH_NAME=%s", branch),
		fmt.Sprintf("REPO_PATH=%s", repoDir),
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build script failed: %w", err)
	}

	fmt.Printf("         [+] Build script completed successfully!\n")
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
	fmt.Printf(`%s v%s - GitHub Webhook Listener for WordPress Plugin Deployment

Usage:
  %s <command> [options] [arguments]

Commands:
  listen [--port PORT] [--secret SECRET]  Start webhook server for GitHub events
  add-repo <username/repo> <script>       Add a new repository configuration
  remove-repo <username/repo>             Remove a repository configuration  
  list-repos                              List all configured repositories
  init                                    Initialize webhook-listener workspace

Options:
  --port PORT          Webhook server port (default: 3000)
  --secret SECRET      GitHub webhook secret for validation

Examples:
  %s init
  %s listen --port 3000 --secret mysecret
  %s add-repo myuser/myapp 'npm run build && cp dist/plugin.zip ./plugin.zip'
  %s remove-repo myuser/myapp
  %s list-repos

`, appName, version, appName, appName, appName, appName, appName, appName)
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

	case "add-repo":
		if len(os.Args) < 4 {
			fmt.Println("Error: add-repo requires repository and script")
			fmt.Println("Usage: webhook-listener add-repo <username/repo> <script>")
			fmt.Println("Example: webhook-listener add-repo myuser/myapp 'npm run build && cp dist/plugin.zip ./plugin.zip'")
			os.Exit(1)
		}

		workDir := filepath.Join(os.Getenv("HOME"), ".webhook-listener")
		configMgr := NewConfigManager(workDir)

		repo := os.Args[2]
		script := os.Args[3]

		if err := configMgr.AddRepoConfig(repo, script); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "remove-repo":
		if len(os.Args) < 3 {
			fmt.Println("Error: remove-repo requires repository name")
			fmt.Println("Usage: webhook-listener remove-repo <username/repo>")
			os.Exit(1)
		}

		workDir := filepath.Join(os.Getenv("HOME"), ".webhook-listener")
		configMgr := NewConfigManager(workDir)

		repo := os.Args[2]

		if err := configMgr.RemoveRepoConfig(repo); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "list-repos":
		workDir := filepath.Join(os.Getenv("HOME"), ".webhook-listener")
		configMgr := NewConfigManager(workDir)

		if err := configMgr.ListRepoConfigs(); err != nil {
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

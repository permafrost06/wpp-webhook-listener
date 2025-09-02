package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// generateRandomSiteName creates a random 8-character site name for webhook deployments
func generateRandomSiteName() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

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

type DeploymentInfo struct {
	Branch string `json:"branch"`
	Link   string `json:"link"`
}

type WebhookServer struct {
	port     string
	secret   string
	deployer *WPPDeployer
}

// NewWebhookServer creates a new webhook server instance
func NewWebhookServer(port, secret string, deployer *WPPDeployer) *WebhookServer {
	// Initialize random seed for site name generation
	rand.Seed(time.Now().UnixNano())

	return &WebhookServer{
		port:     port,
		secret:   secret,
		deployer: deployer,
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
			ws.handleRepositoryDeployment(repo, pr.Head.Ref, payload.Repository.CloneURL)
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

		ws.handleRepositoryDeployment(repo, branch, payload.Repository.CloneURL)

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

func (ws *WebhookServer) handleRepositoryDeployment(repoFullName, branch, cloneURL string) {
	configs, err := ws.deployer.loadRepoConfigs()
	if err != nil {
		fmt.Printf("         [!] Error loading repo configs: %v\n", err)
		return
	}

	repoConfig, exists := configs[repoFullName]
	if !exists {
		fmt.Printf("         [!] Repository %s not configured for deployment\n", repoFullName)
		return
	}

	fmt.Printf("         [+] Repository configured for deployment\n")
	fmt.Printf("         [+] Script: %s\n", repoConfig.Script)

	// Generate random short site name instead of long repo-based name
	randomSiteName := generateRandomSiteName()
	fmt.Printf("         [+] Generated site name: %s\n", randomSiteName)
	fmt.Printf("         [+] Site URL: %s.nshlog.com\n", randomSiteName)
	fmt.Printf("         [+] For repo: %s (branch: %s)\n", repoFullName, branch)

	if err := ws.deployRepository(randomSiteName, repoFullName, branch, cloneURL, repoConfig); err != nil {
		fmt.Printf("         [!] Deployment failed: %v\n", err)
		return
	}

	fmt.Printf("         [✔] Deployment completed successfully!\n")
	fmt.Println()
}

func (ws *WebhookServer) deployRepository(siteName, repoFullName, branch, cloneURL string, config RepoConfig) error {
	workDir := ws.deployer.workDir
	repoDir := filepath.Join(workDir, "repos", repoFullName)

	if err := os.MkdirAll(filepath.Dir(repoDir), 0755); err != nil {
		return fmt.Errorf("failed to create repos directory: %w", err)
	}

	if err := ws.cloneOrUpdateRepo(repoDir, cloneURL, branch); err != nil {
		return fmt.Errorf("failed to clone/update repository: %w", err)
	}

	if err := ws.createOrUpdateSite(siteName); err != nil {
		return fmt.Errorf("failed to create/update site: %w", err)
	}

	if err := ws.createWPWrapper(repoDir, siteName); err != nil {
		return fmt.Errorf("failed to create wp wrapper: %w", err)
	}

	if err := ws.runUserScript(repoDir, config.Script, repoFullName, siteName); err != nil {
		return fmt.Errorf("failed to run user script: %w", err)
	}

	if err := ws.trackDeployment(repoFullName, branch, siteName); err != nil {
		return fmt.Errorf("failed to track deployment: %w", err)
	}

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

func (ws *WebhookServer) createOrUpdateSite(siteName string) error {
	fmt.Printf("         [+] Setting up WordPress site...\n")

	sites, err := ws.deployer.List()
	if err != nil {
		return fmt.Errorf("failed to list sites: %w", err)
	}

	siteExists := false
	for _, site := range sites {
		if site == siteName {
			siteExists = true
			break
		}
	}

	if !siteExists {
		fmt.Printf("         [+] Creating new WordPress site: %s\n", siteName)
		if err := ws.deployer.Deploy(siteName); err != nil {
			return fmt.Errorf("failed to deploy WordPress site: %w", err)
		}
	} else {
		fmt.Printf("         [+] WordPress site already exists: %s\n", siteName)
	}

	return nil
}

func (ws *WebhookServer) createWPWrapper(repoDir, siteName string) error {
	fmt.Printf("         [+] Creating wp wrapper script...\n")

	wrapperScript := fmt.Sprintf(`#!/bin/bash
# wp wrapper - translates WP-CLI commands to Docker execution
SITE_DIR="$HOME/.wpp-deployer/wordpress-%s"
cd "$SITE_DIR"
exec docker compose -f docker-compose.yml run -T --rm wpcli "$@"
`, siteName)

	wpScript := filepath.Join(repoDir, "wp")
	if err := os.WriteFile(wpScript, []byte(wrapperScript), 0755); err != nil {
		return fmt.Errorf("failed to create wp wrapper: %w", err)
	}

	return nil
}

func (ws *WebhookServer) runUserScript(repoDir, script, repoFullName, siteName string) error {
	fmt.Printf("         [+] Running user script: %s\n", script)

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = repoDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environment variables
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("WP_SITE_NAME=%s", siteName),
		fmt.Sprintf("REPO_PATH=/repos/%s", repoFullName),
		fmt.Sprintf("PATH=%s:%s", repoDir, os.Getenv("PATH")), // Add repo dir to PATH so 'wp' command works
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("user script failed: %w", err)
	}

	fmt.Printf("         [+] User script completed successfully!\n")
	return nil
}

func (ws *WebhookServer) getDeploymentsFilePath() string {
	return filepath.Join(ws.deployer.workDir, "html", "deployments.json")
}

func (ws *WebhookServer) loadDeployments() (map[string][]DeploymentInfo, error) {
	deploymentsPath := ws.getDeploymentsFilePath()
	deployments := make(map[string][]DeploymentInfo)

	// If file doesn't exist, return empty map
	if _, err := os.Stat(deploymentsPath); os.IsNotExist(err) {
		return deployments, nil
	}

	data, err := os.ReadFile(deploymentsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read deployments file: %w", err)
	}

	if err := json.Unmarshal(data, &deployments); err != nil {
		return nil, fmt.Errorf("failed to parse deployments file: %w", err)
	}

	return deployments, nil
}

func (ws *WebhookServer) saveDeployments(deployments map[string][]DeploymentInfo) error {
	deploymentsPath := ws.getDeploymentsFilePath()

	// Ensure html directory exists
	htmlDir := filepath.Dir(deploymentsPath)
	if err := os.MkdirAll(htmlDir, 0755); err != nil {
		return fmt.Errorf("failed to create html directory: %w", err)
	}

	data, err := json.MarshalIndent(deployments, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal deployments: %w", err)
	}

	if err := os.WriteFile(deploymentsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write deployments file: %w", err)
	}

	return nil
}

func (ws *WebhookServer) trackDeployment(repoFullName, branch, siteName string) error {
	fmt.Printf("         [+] Tracking deployment in deployments.json...\n")

	deployments, err := ws.loadDeployments()
	if err != nil {
		return fmt.Errorf("failed to load deployments: %w", err)
	}

	// Create the deployment info
	deploymentInfo := DeploymentInfo{
		Branch: branch,
		Link:   fmt.Sprintf("http://%s.nshlog.com/", siteName),
	}

	// Get existing deployments for this repo
	repoDeployments := deployments[repoFullName]

	// Check if this branch already exists and update it, or add new one
	found := false
	for i, existing := range repoDeployments {
		if existing.Branch == branch {
			repoDeployments[i] = deploymentInfo
			found = true
			break
		}
	}

	if !found {
		repoDeployments = append(repoDeployments, deploymentInfo)
	}

	// Update the deployments map
	deployments[repoFullName] = repoDeployments

	// Save to file
	if err := ws.saveDeployments(deployments); err != nil {
		return fmt.Errorf("failed to save deployments: %w", err)
	}

	fmt.Printf("         [+] Deployment tracked: %s -> %s\n", branch, deploymentInfo.Link)
	return nil
}

func (ws *WebhookServer) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "wpp-deployer-webhook",
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
		fmt.Fprintf(w, "wpp-deployer webhook server\nEndpoints:\n  POST /webhook - GitHub webhooks\n  GET /health - Health check\n")
	})

	server := &http.Server{
		Addr:    ":" + ws.port,
		Handler: mux,
	}

	fmt.Printf("🚀 Webhook server starting on port %s\n", ws.port)
	fmt.Println("📋 Endpoints:")
	fmt.Printf("    POST http://localhost:%s/webhook - GitHub webhooks\n", ws.port)
	fmt.Printf("    GET  http://localhost:%s/health  - Health check\n", ws.port)
	fmt.Println()
	fmt.Println("🔗 Configure GitHub webhook URL: http://your-domain.com/webhook")
	fmt.Println("📝 Listening for GitHub events...")
	fmt.Println()

	return server.ListenAndServe()
}

func (w *WPPDeployer) Listen(port, secret string) error {
	if port == "" {
		port = "3000"
	}

	server := NewWebhookServer(port, secret, w)
	return server.Start()
}


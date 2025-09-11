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

type RepoConfig struct {
	ID            int
	Repo          string
	ZipPaths      []string
	CustomScript  string
	WpcliCommands string
	Created       time.Time
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
	queries := []string{
		`CREATE TABLE IF NOT EXISTS deployments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT NOT NULL,
			branch TEXT NOT NULL,
			sitename TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(repo, branch)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT NOT NULL UNIQUE,
			custom_script TEXT,
			wpcli_commands TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS repo_zips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo_config_id INTEGER NOT NULL,
			zip_path TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (repo_config_id) REFERENCES repo_configs (id)
		);`,
	}

	for _, query := range queries {
		if _, err := ws.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %v", err)
		}
	}

	return nil
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

	// Handle workflow_run events separately
	if eventType == "workflow_run" {
		var workflowPayload WorkflowRunPayload
		if err := json.Unmarshal(body, &workflowPayload); err != nil {
			log.Printf("Error parsing workflow_run payload: %v", err)
			http.Error(w, "Error parsing JSON", http.StatusBadRequest)
			return
		}
		ws.handleWorkflowRunEvent(&workflowPayload)
	} else {
		// Handle other events with existing payload structure
		var payload GitHubPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			log.Printf("Error parsing JSON payload: %v", err)
			http.Error(w, "Error parsing JSON", http.StatusBadRequest)
			return
		}
		ws.handleGitHubEvent(eventType, &payload)
	}

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

func (ws *WebhookServer) handleWorkflowRunEvent(payload *WorkflowRunPayload) {
	timestamp := time.Now().Format("15:04:05")
	repo := payload.Repository.FullName
	run := payload.WorkflowRun

	// Print workflow run information
	fmt.Printf("[%s] ⚙️  Workflow Run: %s\n", timestamp, run.Name)
	fmt.Printf("         Repository: %s\n", repo)
	fmt.Printf("         Action: %s\n", payload.Action)
	fmt.Printf("         Status: %s\n", run.Status)
	if run.Conclusion != "" {
		fmt.Printf("         Conclusion: %s\n", run.Conclusion)
	}
	fmt.Printf("         Branch: %s\n", run.HeadBranch)
	fmt.Printf("         Commit: %s\n", run.HeadSHA[:8])
	fmt.Printf("         Run Number: #%d\n", run.RunNumber)
	fmt.Printf("         Event: %s\n", run.Event)
	fmt.Printf("         URL: %s\n", run.HTMLURL)

	// If the workflow run is completed, fetch artifacts
	if payload.Action == "completed" {
		ws.fetchAndDisplayArtifacts(repo, run.ID, payload.Installation.ID)
	}

	fmt.Println()
}

func (ws *WebhookServer) generateGitHubAppJWT() (string, error) {
	appID := os.Getenv("GITHUB_APP_ID")
	privateKeyPath := os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH")
	privateKeyData := os.Getenv("GITHUB_APP_PRIVATE_KEY")

	if appID == "" {
		return "", fmt.Errorf("GITHUB_APP_ID not set")
	}

	var privateKeyBytes []byte
	var err error

	if privateKeyPath != "" {
		privateKeyBytes, err = os.ReadFile(privateKeyPath)
	} else if privateKeyData != "" {
		privateKeyBytes = []byte(privateKeyData)
	} else {
		return "", fmt.Errorf("neither GITHUB_APP_PRIVATE_KEY_PATH nor GITHUB_APP_PRIVATE_KEY is set")
	}

	if err != nil {
		return "", fmt.Errorf("failed to read private key: %v", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	now := time.Now()
	claims := &GitHubAppClaims{
		Iat: now.Unix(),
		Exp: now.Add(10 * time.Minute).Unix(), // GitHub requires max 10 minutes
		Iss: appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func (ws *WebhookServer) getInstallationTokenByID(installationID int64) (string, error) {
	jwtToken, err := ws.generateGitHubAppJWT()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get installation token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("GitHub API error: %s", resp.Status)
	}

	var tokenResp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	return tokenResp.Token, nil
}

func (ws *WebhookServer) fetchAndDisplayArtifacts(repo string, runID int64, installationID int64) {
	// Get installation access token
	apiToken, err := ws.getInstallationTokenByID(installationID)
	if err != nil {
		fmt.Printf("         [⚠️] Failed to get GitHub App token: %v\n", err)
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/artifacts", repo, runID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating artifacts request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching artifacts: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("GitHub API error: %s", resp.Status)
		return
	}

	var artifactsResp ArtifactsResponse
	if err := json.NewDecoder(resp.Body).Decode(&artifactsResp); err != nil {
		log.Printf("Error parsing artifacts response: %v", err)
		return
	}

	// Display artifact information
	fmt.Printf("         📦 Artifacts (%d total):\n", artifactsResp.TotalCount)
	if artifactsResp.TotalCount == 0 {
		fmt.Printf("           No artifacts found\n")
		return
	}

	for _, artifact := range artifactsResp.Artifacts {
		fmt.Printf("           - %s (%d bytes)\n", artifact.Name, artifact.SizeInBytes)
		fmt.Printf("             ID: %d\n", artifact.ID)
		fmt.Printf("             Created: %s\n", artifact.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("             Expires: %s\n", artifact.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("             Download URL: %s\n", artifact.ArchiveDownloadURL)
		if artifact.Expired {
			fmt.Printf("             Status: ⚠️ EXPIRED\n")
		} else {
			fmt.Printf("             Status: ✅ Available\n")
		}
		fmt.Println()
	}
}

func (ws *WebhookServer) buildPluginAndDeploySite(repo string, branch string) {
	// Check if repo is configured in database
	var count int
	err := ws.db.QueryRow("SELECT COUNT(*) FROM repo_configs WHERE repo = ?", strings.ToLower(repo)).Scan(&count)
	if err != nil {
		log.Printf("Error checking repo configuration for %s: %v", repo, err)
		return
	}

	if count == 0 {
		log.Printf("Repository %s is not configured, skipping", repo)
		return
	}

	go func() {
		log.Printf("Starting build and deploy process for %s:%s", repo, branch)

		if err := ws.processRepoDeployment(strings.ToLower(repo), branch); err != nil {
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

func (ws *WebhookServer) getRepoConfig(repo string) (*RepoConfig, error) {
	var configID int
	var customScript, wpcliCommands sql.NullString

	err := ws.db.QueryRow("SELECT id, custom_script, wpcli_commands FROM repo_configs WHERE repo = ?", repo).Scan(&configID, &customScript, &wpcliCommands)
	if err != nil {
		return nil, fmt.Errorf("repo config not found for %s: %v", repo, err)
	}

	rows, err := ws.db.Query("SELECT zip_path FROM repo_zips WHERE repo_config_id = ?", configID)
	if err != nil {
		return nil, fmt.Errorf("failed to query zip paths for repo %s: %v", repo, err)
	}
	defer rows.Close()

	var zipPaths []string
	for rows.Next() {
		var zipPath string
		if err := rows.Scan(&zipPath); err != nil {
			return nil, fmt.Errorf("failed to scan zip path: %v", err)
		}
		zipPaths = append(zipPaths, zipPath)
	}

	if len(zipPaths) == 0 {
		return nil, fmt.Errorf("no zip paths configured for repo %s", repo)
	}

	return &RepoConfig{
		ID:            configID,
		Repo:          repo,
		ZipPaths:      zipPaths,
		CustomScript:  customScript.String,
		WpcliCommands: wpcliCommands.String,
	}, nil
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

	repoConfig, err := ws.getRepoConfig(repo)
	if err != nil {
		return fmt.Errorf("no configuration found for repo %s: %v", repo, err)
	}

	repoURL := fmt.Sprintf("https://github.com/%s", repo)

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
	}

	var scriptPath string
	if repoConfig.CustomScript != "" {
		scriptContent := repoConfig.CustomScript
		if !strings.HasPrefix(scriptContent, "#!") {
			scriptContent = "#!/bin/bash\nset -e\n" + scriptContent
		}

		tmpFile, err := os.CreateTemp("", fmt.Sprintf("build-script-%s-*.sh", deployment.Sitename))
		if err != nil {
			return fmt.Errorf("failed to create temp script file: %v", err)
		}

		if _, err := tmpFile.WriteString(scriptContent); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to write script content: %v", err)
		}

		if err := tmpFile.Close(); err != nil {
			os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to close temp script file: %v", err)
		}

		if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
			os.Remove(tmpFile.Name())
			return fmt.Errorf("failed to make script executable: %v", err)
		}

		scriptPath := tmpFile.Name()

		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/usr/local/bin/project-build.sh", scriptPath))
		log.Printf("Mounted custom build script: %s", scriptPath)
	}

	dockerArgs = append(dockerArgs, "project-builder", repoURL, branch)
	dockerArgs = append(dockerArgs, repoConfig.ZipPaths...)

	log.Printf("Building %d zip files: %v", len(repoConfig.ZipPaths), repoConfig.ZipPaths)
	output, err = exec.Command("docker", dockerArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker build failed: %v, output: %s", err, string(output))
	}

	defer os.Remove(scriptPath)

	siteDir := filepath.Join(homeDir, ".wpp-deployer", fmt.Sprintf("wordpress-%s", deployment.Sitename))

	log.Printf("Installing %d plugins on site %s", len(repoConfig.ZipPaths), deployment.Sitename)

	for _, zipPath := range repoConfig.ZipPaths {
		builtZipPath := filepath.Join(absOutputDir, filepath.Base(zipPath))
		if _, err := os.Stat(builtZipPath); os.IsNotExist(err) {
			log.Printf("Warning: expected zip file not found: %s", builtZipPath)
			continue
		}

		log.Printf("Installing plugin: %s", filepath.Base(zipPath))

		cmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "run", "-T", "--rm", "wpcli",
			"plugin", "install", fmt.Sprintf("/zips/%s", filepath.Base(zipPath)), "--activate", "--force")
		cmd.Dir = siteDir

		output, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("Plugin installation failed for %s: %v, output: %s", filepath.Base(zipPath), err, string(output))
		} else {
			log.Printf("Successfully installed plugin: %s", filepath.Base(zipPath))
		}
	}

	if repoConfig.WpcliCommands != "" {
		log.Printf("Executing post-install wpcli commands for %s", deployment.Sitename)
		cmdList := strings.Split(repoConfig.WpcliCommands, "\n")

		for _, cmdLine := range cmdList {
			cmdLine = strings.TrimSpace(cmdLine)
			if cmdLine == "" {
				continue
			}

			log.Printf("Executing wpcli command: %s", cmdLine)

			if !strings.HasPrefix(cmdLine, "wp ") {
				log.Printf("Skipping non-wp command: %s", cmdLine)
				continue
			}

			wpArgs := strings.Fields(cmdLine[3:])

			dockerCmd := []string{"compose", "-f", "docker-compose.yml", "run", "-T", "--rm", "wpcli"}
			dockerCmd = append(dockerCmd, wpArgs...)

			cmd := exec.Command("docker", dockerCmd...)
			cmd.Dir = siteDir

			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("wpcli command '%s' failed: %v, output: %s", cmdLine, err, string(output))
			}

			log.Printf("Command output: %s", strings.TrimSpace(string(output)))
		}

		log.Printf("Successfully executed post-install wpcli commands")
	}

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

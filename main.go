package main

import (
	"archive/zip"
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

func (ws *WebhookServer) initDB() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS repositories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT NOT NULL UNIQUE,
			build_mode TEXT NOT NULL CHECK (build_mode IN ('docker', 'github_workflow')),
			wpcli_commands TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS docker_build_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repository_id INTEGER NOT NULL UNIQUE,
			custom_script TEXT NOT NULL,
			zip_paths JSON NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (repository_id) REFERENCES repositories (id)
		);`,
		`CREATE TABLE IF NOT EXISTS github_workflow_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repository_id INTEGER NOT NULL UNIQUE,
			workflow_name TEXT,
			artifact_names JSON NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (repository_id) REFERENCES repositories (id)
		);`,
		`CREATE TABLE IF NOT EXISTS deployments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT,
			branch TEXT,
			sitename TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(repo, branch)
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
					if err := ws.deployPlugins(&repoConfig, run.HeadBranch, nil, ws.retrieveWorkflowArtifacts); err != nil {
						log.Printf("Error processing github workflow deployment for %s:%s - %v", repo, run.HeadBranch, err)
					}
				}()
			} else {
				log.Printf("Repository not configured to use github workflow artifacts, ignoring github workflow success event.")
			}
		}

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

	return nil
}

func (ws *WebhookServer) retrieveWorkflowArtifacts(branch, sitename string, repoConfig *RepositoryConfig, payload *WorkflowRunPayload) ([]string, error) {
	var workflowName sql.NullString
	var artifactNamesJSON string

	err := ws.db.QueryRow(`
		SELECT workflow_name, artifact_names 
		FROM github_workflow_configs 
		WHERE repository_id = ?`, repoConfig.ID).Scan(
		&workflowName, &artifactNamesJSON)

	if err != nil {
		return nil, fmt.Errorf("GitHub workflow config not found: %v", err)
	}

	var artifactNames []string
	if err := json.Unmarshal([]byte(artifactNamesJSON), &artifactNames); err != nil {
		return nil, fmt.Errorf("failed to parse artifact names JSON: %v", err)
	}

	var workflowNamePtr *string
	if workflowName.Valid {
		workflowNamePtr = &workflowName.String
	}

	var workflowConfig = GitHubWorkflowConfig{
		RepositoryConfig: *repoConfig,
		WorkflowName:     workflowNamePtr,
		ArtifactNames:    artifactNames,
	}

	if workflowConfig.WorkflowName != nil && *workflowConfig.WorkflowName != payload.WorkflowRun.Name {
		return nil, fmt.Errorf("Workflow %s not configured for repo %s", payload.WorkflowRun.Name, repoConfig.Repo)
	}

	repo := strings.ToLower(payload.Repository.FullName)

	apiToken, err := ws.getInstallationTokenByID(payload.Installation.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get GitHub App token: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/artifacts", payload.Repository.FullName, payload.WorkflowRun.ID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating artifacts request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching artifacts: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API error: %s", resp.Status)
	}

	var artifactsResp ArtifactsResponse
	if err := json.NewDecoder(resp.Body).Decode(&artifactsResp); err != nil {
		return nil, fmt.Errorf("error parsing artifacts response: %v", err)
	}

	var downloadedFiles []string
	matchingArtifacts := make(map[string]bool)
	for _, name := range workflowConfig.ArtifactNames {
		matchingArtifacts[name] = true
	}

	log.Printf("Looking for artifacts matching: %v", workflowConfig.ArtifactNames)

	outputDir := filepath.Join(ws.dotPath, "docker-build-output", sitename)

	for _, artifact := range artifactsResp.Artifacts {
		if !matchingArtifacts[artifact.Name] {
			log.Printf("Skipping artifact '%s' - not in configured list", artifact.Name)
			continue
		}

		if artifact.Expired {
			log.Printf("Skipping artifact '%s' - expired", artifact.Name)
			continue
		}

		log.Printf("Downloading artifact: %s (%d bytes)", artifact.Name, artifact.SizeInBytes)

		downloadReq, err := http.NewRequest("GET", artifact.ArchiveDownloadURL, nil)
		if err != nil {
			log.Printf("Error creating download request for %s: %v", artifact.Name, err)
			continue
		}

		downloadReq.Header.Set("Authorization", "Bearer "+apiToken)
		downloadReq.Header.Set("Accept", "application/vnd.github+json")
		downloadReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		downloadResp, err := client.Do(downloadReq)
		if err != nil {
			log.Printf("Error downloading artifact %s: %v", artifact.Name, err)
			continue
		}
		defer downloadResp.Body.Close()

		if downloadResp.StatusCode != 200 {
			log.Printf("GitHub API error downloading %s: %s", artifact.Name, downloadResp.Status)
			continue
		}

		artifactPath := filepath.Join(outputDir, fmt.Sprintf("%s.zip", artifact.Name))
		artifactFile, err := os.Create(artifactPath)
		if err != nil {
			log.Printf("Error creating file for artifact %s: %v", artifact.Name, err)
			continue
		}

		_, err = io.Copy(artifactFile, downloadResp.Body)
		artifactFile.Close()

		if err != nil {
			log.Printf("Error saving artifact %s: %v", artifact.Name, err)
			os.Remove(artifactPath)
			continue
		}

		log.Printf("Successfully downloaded artifact: %s", artifact.Name)
		downloadedFiles = append(downloadedFiles, artifactPath)

		log.Printf("Unzip artifact: %s", artifact.Name)
		absZipPath, err := filepath.Abs(artifactPath)
		if err != nil {
			log.Printf("Error getting absolute path for zip %s: %v", artifact.Name, err)
		}
		expandIfNestedZip(absZipPath)
	}

	log.Printf("Downloaded %d matching artifacts to %s", len(downloadedFiles), outputDir)

	if len(downloadedFiles) == 0 {
		return nil, fmt.Errorf("No matching artifacts found for %s", repo)
	}

	log.Printf("Using site: %s for %s:%s", sitename, repo, branch)

	log.Printf("Successfully retrieved GitHub workflow artifacts for workflow %s on %s:%s", payload.WorkflowRun.Name, repo, branch)

	return []string{}, nil
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

func (ws *WebhookServer) deploySiteOrUseExisting(repo string, branch string) (*Deployment, error) {
	var deployment Deployment

	err := ws.db.QueryRow(
		"SELECT id, repo, branch, sitename, description, created_at FROM deployments WHERE repo = ? AND branch = ?",
		repo, branch,
	).Scan(&deployment.ID, &deployment.Repo, &deployment.Branch, &deployment.Sitename, &deployment.Description, &deployment.Created)

	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query deployment: %v", err)
	}

	if err == sql.ErrNoRows {
		const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, 8)
		rand.Read(b)
		for i := range b {
			b[i] = chars[b[i]%byte(len(chars))]
		}
		sitename := string(b)

		output, err := exec.Command("wpp-deployer", "list").Output()
		if err != nil {
			return nil, fmt.Errorf("failed to list deployments: %v", err)
		}

		if !strings.Contains(string(output), sitename) {
			log.Printf("Deploying new site: %s", sitename)
			if err := exec.Command("wpp-deployer", "deploy", sitename).Run(); err != nil {
				return nil, fmt.Errorf("failed to deploy site %s: %v", sitename, err)
			}
			log.Printf("Successfully deployed site: %s", sitename)
		} else {
			log.Printf("Site %s already exists", sitename)
		}

		_, err = ws.db.Exec(
			"INSERT INTO deployments (repo, branch, sitename) VALUES (?, ?, ?)",
			repo, branch, sitename,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert deployment: %v", err)
		}

		deployment.Repo = &repo
		deployment.Branch = &branch
		deployment.Sitename = sitename
		deployment.Created = time.Now()

		return &deployment, nil
	}

	return nil, nil
}

func (ws *WebhookServer) deployPlugins(
	repoConfig *RepositoryConfig,
	branch string,
	workflowPayload *WorkflowRunPayload,
	buildStep func(branch string, sitename string, repoConfig *RepositoryConfig, workflowPayload *WorkflowRunPayload) ([]string, error),
) error {
	repo := repoConfig.Repo

	deployment, err := ws.deploySiteOrUseExisting(repo, branch)
	if err != nil {
		return fmt.Errorf("Failed to deploy new site or get existing: %v", err)
	}

	pluginZips, err := buildStep(branch, deployment.Sitename, repoConfig, workflowPayload)
	if err != nil {
		return fmt.Errorf("Build step failed: %v", err)
	}

	if err := ws.installPlugins(pluginZips, deployment.Sitename); err != nil {
		return fmt.Errorf("plugin installation failed: %v", err)
	}

	if err := ws.executeWpCliCommands(repoConfig.WpcliCommands, deployment.Sitename); err != nil {
		return fmt.Errorf("wp-cli commands failed: %v", err)
	}

	log.Printf("Successfully completed build and deploy for %s:%s on site %s", repo, branch, deployment.Sitename)
	return nil
}

func (ws *WebhookServer) buildWithDocker(branch, sitename string, repoConfig *RepositoryConfig, workflowPayload *WorkflowRunPayload) ([]string, error) {
	var customScript string
	var zipPathsJSON string

	err := ws.db.QueryRow(`
		SELECT custom_script, zip_paths 
		FROM docker_build_configs 
		WHERE repository_id = ?`, repoConfig.ID).Scan(&customScript, &zipPathsJSON)

	if err != nil {
		return nil, fmt.Errorf("docker build config not found: %v", err)
	}

	var zipPaths []string
	if err := json.Unmarshal([]byte(zipPathsJSON), &zipPaths); err != nil {
		return nil, fmt.Errorf("failed to parse zip paths JSON: %v", err)
	}

	var dockerConfig = DockerBuildConfig{
		RepositoryConfig: *repoConfig,
		CustomScript:     customScript,
		ZipPaths:         zipPaths,
	}

	repo := dockerConfig.Repo
	log.Printf("Building %s:%s with Docker", repo, branch)

	repoURL := fmt.Sprintf("https://github.com/%s", dockerConfig.Repo)

	absOutputDir, err := filepath.Abs(filepath.Join(ws.dotPath, "docker-build-output", sitename))
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for output dir: %v", err)
	}

	absStoreDir, err := filepath.Abs(filepath.Join(ws.dotPath, "pnpm-store"))
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for pnpm store dir: %v", err)
	}

	dockerArgs := []string{
		"run", "-v", fmt.Sprintf("%s:/output", absOutputDir),
		"-v", fmt.Sprintf("%s:/pnpm/store", absStoreDir),
	}

	var scriptPath string
	if dockerConfig.CustomScript != "" {
		scriptContent := dockerConfig.CustomScript
		if !strings.HasPrefix(scriptContent, "#!") {
			scriptContent = "#!/bin/bash\nset -e\n" + scriptContent
		}

		tmpFile, err := os.CreateTemp("", fmt.Sprintf("build-script-%s-*.sh", sitename))
		if err != nil {
			return nil, fmt.Errorf("failed to create temp script file: %v", err)
		}

		if _, err := tmpFile.WriteString(scriptContent); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("failed to write script content: %v", err)
		}

		if err := tmpFile.Close(); err != nil {
			os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("failed to close temp script file: %v", err)
		}

		if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
			os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("failed to make script executable: %v", err)
		}

		scriptPath = tmpFile.Name()
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/usr/local/bin/project-build.sh", scriptPath))
		log.Printf("Mounted custom build script: %s", scriptPath)
	}

	dockerArgs = append(dockerArgs, "project-builder", repoURL, branch)
	dockerArgs = append(dockerArgs, dockerConfig.ZipPaths...)

	log.Printf("Building %d zip files: %v", len(dockerConfig.ZipPaths), dockerConfig.ZipPaths)
	output, err := exec.Command("docker", dockerArgs...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker build failed: %v, output: %s", err, string(output))
	}

	if scriptPath != "" {
		defer os.Remove(scriptPath)
	}

	var zipFiles []string
	for _, zipPath := range dockerConfig.ZipPaths {
		builtZipPath := filepath.Join(absOutputDir, filepath.Base(zipPath))
		if _, err := os.Stat(builtZipPath); os.IsNotExist(err) {
			log.Printf("Warning: expected zip file not found: %s", builtZipPath)
			continue
		}
		zipFiles = append(zipFiles, builtZipPath)
	}

	log.Printf("Successfully completed build for %s:%s", repo, branch)

	return zipFiles, nil
}

func (ws *WebhookServer) installPlugins(zipFiles []string, sitename string) error {
	if len(zipFiles) == 0 {
		log.Printf("No zip files to install")
		return nil
	}

	siteDir := filepath.Join(ws.dotPath, fmt.Sprintf("wordpress-%s", sitename))

	log.Printf("Installing %d plugins on site %s", len(zipFiles), sitename)

	for _, zipFile := range zipFiles {
		log.Printf("Installing plugin: %s", filepath.Base(zipFile))

		cmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "run", "-T", "--rm", "wpcli",
			"plugin", "install", fmt.Sprintf("/zips/%s", filepath.Base(zipFile)), "--activate", "--force")
		cmd.Dir = siteDir

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Plugin installation failed for %s: %v, output: %s", filepath.Base(zipFile), err, string(output))
		} else {
			log.Printf("Successfully installed plugin: %s", filepath.Base(zipFile))
		}
	}

	return nil
}

func (ws *WebhookServer) executeWpCliCommands(wpcliCommands, sitename string) error {
	if wpcliCommands == "" {
		return nil
	}

	siteDir := filepath.Join(ws.dotPath, fmt.Sprintf("wordpress-%s", sitename))

	log.Printf("Executing post-install wpcli commands for %s", sitename)
	cmdList := strings.SplitSeq(wpcliCommands, "\n")

	for cmdLine := range cmdList {
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
	return nil
}

func expandIfNestedZip(absZipPath string) error {
	log.Printf("%s", absZipPath)

	r, err := zip.OpenReader(absZipPath)
	if err != nil {
		return fmt.Errorf("Couldn't open zip file %s: %v", absZipPath, err)
	}
	defer r.Close()

	if len(r.File) != 1 {
		return nil
	}

	if filepath.Ext(r.File[0].Name) == ".zip" {
		log.Printf("Zip contains only another zip file: %s\n", r.File[0].Name)
		log.Printf("Unzip nested zip: %s", absZipPath)
		cmd := exec.Command("unzip", "-o", absZipPath)
		cmd.Dir = filepath.Dir(absZipPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf(
				"unzip failed for file %s: %v, output: %s",
				absZipPath,
				err,
				string(output),
			)
		}

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

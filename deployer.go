package main

import (
	"archive/zip"
	"crypto/rand"
	"database/sql"
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

func (ws *WebhookServer) deploySiteOrUseExisting(repo string, branch string) (*Deployment, error) {
	var deployment Deployment

	err := ws.db.QueryRow(
		"SELECT id, repo, branch, sitename, description, created_at FROM deployments WHERE repo = ? AND branch = ?",
		repo, branch,
	).Scan(&deployment.ID, &deployment.Repo, &deployment.Branch, &deployment.Sitename, &deployment.Description, &deployment.Created)

	if err == nil {
		return &deployment, nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query deployment: %v", err)
	}

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

	return downloadedFiles, nil
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


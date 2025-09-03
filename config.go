package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type RepoConfig struct {
	Repo   string `json:"repo"`
	Script string `json:"script"`
}

type ConfigManager struct {
	workDir string
}

func NewConfigManager(workDir string) *ConfigManager {
	return &ConfigManager{
		workDir: workDir,
	}
}

func (cm *ConfigManager) GetWorkDir() string {
	return cm.workDir
}

func (cm *ConfigManager) getConfigPath() string {
	return filepath.Join(cm.workDir, "repos.json")
}

func (cm *ConfigManager) loadConfigs() (map[string]RepoConfig, error) {
	configPath := cm.getConfigPath()
	configs := make(map[string]RepoConfig)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return configs, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read repo configs: %w", err)
	}

	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse repo configs: %w", err)
	}

	return configs, nil
}

func (cm *ConfigManager) saveConfigs(configs map[string]RepoConfig) error {
	configPath := cm.getConfigPath()

	if err := os.MkdirAll(cm.workDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}

	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal repo configs: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write repo configs: %w", err)
	}

	return nil
}

func (cm *ConfigManager) GetRepoConfig(repo string) (*RepoConfig, error) {
	configs, err := cm.loadConfigs()
	if err != nil {
		return nil, err
	}

	config, exists := configs[repo]
	if !exists {
		return nil, fmt.Errorf("repository %s not configured", repo)
	}

	return &config, nil
}

func (cm *ConfigManager) AddRepoConfig(repo, script string) error {
	if repo == "" {
		return fmt.Errorf("repository name is required")
	}
	if script == "" {
		return fmt.Errorf("script is required")
	}

	if !strings.Contains(repo, "/") {
		return fmt.Errorf("repository should be in format 'username/repo-name'")
	}

	configs, err := cm.loadConfigs()
	if err != nil {
		return err
	}

	if _, exists := configs[repo]; exists {
		return fmt.Errorf("repository '%s' already exists", repo)
	}

	configs[repo] = RepoConfig{
		Repo:   repo,
		Script: script,
	}

	if err := cm.saveConfigs(configs); err != nil {
		return err
	}

	fmt.Printf("✔ Repository configuration added:\n")
	fmt.Printf("    Repository: %s\n", repo)
	fmt.Printf("    Script: %s\n", script)

	return nil
}

func (cm *ConfigManager) RemoveRepoConfig(repo string) error {
	if repo == "" {
		return fmt.Errorf("repository name is required")
	}

	configs, err := cm.loadConfigs()
	if err != nil {
		return err
	}

	if _, exists := configs[repo]; !exists {
		return fmt.Errorf("repository '%s' not found", repo)
	}

	delete(configs, repo)

	if err := cm.saveConfigs(configs); err != nil {
		return err
	}

	fmt.Printf("✔ Repository configuration removed: %s\n", repo)
	return nil
}

func (cm *ConfigManager) ListRepoConfigs() error {
	configs, err := cm.loadConfigs()
	if err != nil {
		return err
	}

	if len(configs) == 0 {
		fmt.Println("No repositories configured.")
		return nil
	}

	fmt.Printf("Configured repositories (%d):\n\n", len(configs))
	for repo, config := range configs {
		fmt.Printf("  %s\n", repo)
		fmt.Printf("    Script: %s\n", config.Script)
		fmt.Println()
	}

	return nil
}

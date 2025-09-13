package main

import (
	"fmt"
)

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


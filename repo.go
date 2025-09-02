type RepoConfig struct {
	Repo   string `json:"repo"`
	Script string `json:"script"`
}

func (w *WPPDeployer) getRepoConfigPath() string {
	return filepath.Join(w.workDir, "repos.json")
}

func (w *WPPDeployer) loadRepoConfigs() (map[string]RepoConfig, error) {
	configPath := w.getRepoConfigPath()
	configs := make(map[string]RepoConfig)

	// If file doesn't exist, return empty map
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

func (w *WPPDeployer) saveRepoConfigs(configs map[string]RepoConfig) error {
	configPath := w.getRepoConfigPath()

	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal repo configs: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write repo configs: %w", err)
	}

	return nil
}

func (w *WPPDeployer) AddRepo(repo, script string) error {
	if repo == "" {
		return fmt.Errorf("repository name is required")
	}
	if script == "" {
		return fmt.Errorf("script is required")
	}

	// Validate repo format (should be username/repo-name)
	if !strings.Contains(repo, "/") {
		return fmt.Errorf("repository should be in format 'username/repo-name'")
	}

	configs, err := w.loadRepoConfigs()
	if err != nil {
		return err
	}

	// Check if repo already exists
	if _, exists := configs[repo]; exists {
		return fmt.Errorf("repository '%s' already exists", repo)
	}

	configs[repo] = RepoConfig{
		Repo:   repo,
		Script: script,
	}

	if err := w.saveRepoConfigs(configs); err != nil {
		return err
	}

	fmt.Printf("[✔] Repository configuration added:\n")
	fmt.Printf("    Repository: %s\n", repo)
	fmt.Printf("    Script: %s\n", script)

	return nil
}

func (w *WPPDeployer) ListRepos() error {
	configs, err := w.loadRepoConfigs()
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

func printUsage() {
	fmt.Printf(`%s v%s - WordPress Site Deployer

Usage:
  %s <command> [options] [arguments]

Commands:
  install                           Set up %s workspace in ~/.%s
  deploy <sitename>                 Deploy a new WordPress site
  delete <sitename>                 Delete an existing WordPress site
  list                              List all WordPress sites
  exec [-r] <sitename> <args...>    Run docker-compose command on specific site
  exec-all [-r] <args...>           Run docker-compose command on all sites
  listen [--port PORT] [--secret SECRET]  Start webhook server for GitHub events
  add-repo <username/repo> <script>  Add a new repository for deployment
  list-repos                          List all configured repositories

Options:
  -r                   Reload nginx after command execution
  --port PORT          Webhook server port (default: 3000)
  --secret SECRET      GitHub webhook secret for validation

Examples:
  %s install
  %s deploy mysite
  %s delete mysite
  %s list
  %s exec mysite up -d
  %s exec -r mysite down --volumes
  %s exec mysite ps
  %s exec-all -r restart
  %s exec-all ps
  %s listen --port 3000 --secret mysecret
  %s add-repo myuser/myapp 'npm run build && wp plugin install \\$REPO_PATH/dist/plugin.zip --activate'
  %s add-repo myuser/site 'npm run build && wp theme install \\$REPO_PATH/dist/theme.zip --activate'
  %s list-repos

`, appName, version, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	deployer, err := NewWPPDeployer()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	switch command {
	case "listen":
		port := "3000"
		secret := ""

		// Parse arguments for port and secret
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

		if err := deployer.Listen(port, secret); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "add-repo":
		if len(os.Args) < 4 {
			fmt.Println("Error: add-repo requires repository and script")
			fmt.Println("Usage: wpp-deployer add-repo <username/repo> <script>")
			fmt.Println("Example: wpp-deployer add-repo myuser/myapp 'npm run build && wp plugin install \\$REPO_PATH/dist/plugin.zip --activate'")
			fmt.Println("Example: wpp-deployer add-repo myuser/site 'npm run build && wp theme install \\$REPO_PATH/dist/theme.zip --activate && wp db import \\$REPO_PATH/data.sql'")
			os.Exit(1)
		}

		repo := os.Args[2]
		script := os.Args[3]

		if err := deployer.AddRepo(repo, script); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "list":
		sites, err := deployer.List()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		for _, sitename := range sites {
			fmt.Println(sitename)
		}

	case "list-repos":
		if err := deployer.ListRepos(); err != nil {
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


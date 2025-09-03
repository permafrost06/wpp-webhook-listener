package main

import (
	"fmt"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strings"
)

type DeployerClient struct{}

func NewDeployerClient() *DeployerClient {
	return &DeployerClient{}
}

func (dc *DeployerClient) generateSiteName(repoName string) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func (dc *DeployerClient) DeployWithPlugin(repoDir, repoFullName, branch string) (string, error) {
	siteName := dc.generateSiteName(repoFullName)

	fmt.Printf("         [+] Generated site name: %s\n", siteName)
	fmt.Printf("         [+] Deploying WordPress site with wpp-deployer...\n")

	if err := dc.checkWPPDeployerAvailable(); err != nil {
		return "", fmt.Errorf("wpp-deployer not available: %w", err)
	}

	if err := dc.deploySite(siteName); err != nil {
		return "", fmt.Errorf("failed to deploy site: %w", err)
	}

	if err := dc.installPlugin(siteName, repoDir); err != nil {
		return "", fmt.Errorf("failed to install plugin: %w", err)
	}

	return siteName, nil
}

func (dc *DeployerClient) checkWPPDeployerAvailable() error {
	cmd := exec.Command("wpp-deployer", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wpp-deployer command not found or not working")
	}
	return nil
}

func (dc *DeployerClient) deploySite(siteName string) error {
	fmt.Printf("         [+] Creating WordPress site: %s\n", siteName)

	cmd := exec.Command("wpp-deployer", "deploy", siteName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wpp-deployer deploy failed: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("         [+] WordPress site created successfully\n")
	return nil
}

func (dc *DeployerClient) installPlugin(siteName, repoDir string) error {
	fmt.Printf("         [+] Installing plugin from repository...\n")

	pluginPath := filepath.Join(repoDir, "plugin.zip")
	if _, err := exec.LookPath("wpp-deployer"); err != nil {
		return fmt.Errorf("wpp-deployer command not found in PATH")
	}

	homeDir := "/home/" + getCurrentUser()
	siteDir := filepath.Join(homeDir, ".wpp-deployer", "wordpress-"+siteName)

	if pluginExists(pluginPath) {
		fmt.Printf("         [+] Found plugin.zip, installing plugin...\n")

		wpCmd := fmt.Sprintf("cd %s && docker compose -f docker-compose.yml run -T --rm wpcli plugin install %s --activate",
			siteDir, pluginPath)

		cmd := exec.Command("bash", "-c", wpCmd)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("         [!] Plugin installation failed (continuing anyway): %s\n", string(output))
		} else {
			fmt.Printf("         [+] Plugin installed and activated successfully\n")
		}
	} else {
		fmt.Printf("         [+] No plugin.zip found, assuming theme or other deployment\n")

		themeDir := filepath.Join(repoDir, "theme")
		if dirExists(themeDir) {
			fmt.Printf("         [+] Found theme directory, installing theme...\n")

			wpCmd := fmt.Sprintf("cd %s && docker compose -f docker-compose.yml run -T --rm wpcli theme install %s --activate",
				siteDir, themeDir)

			cmd := exec.Command("bash", "-c", wpCmd)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("         [!] Theme installation failed (continuing anyway): %s\n", string(output))
			} else {
				fmt.Printf("         [+] Theme installed and activated successfully\n")
			}
		}
	}

	return nil
}

func getCurrentUser() string {
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		return "user"
	}
	return strings.TrimSpace(string(output))
}

func pluginExists(path string) bool {
	cmd := exec.Command("test", "-f", path)
	return cmd.Run() == nil
}

func dirExists(path string) bool {
	cmd := exec.Command("test", "-d", path)
	return cmd.Run() == nil
}

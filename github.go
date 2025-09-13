package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

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


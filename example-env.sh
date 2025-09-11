#!/bin/bash
# Example environment variables for GitHub Actions support
# Copy this file to env.sh and update with your actual values

# GitHub App Configuration
export GITHUB_APP_ID="123456"  # Replace with your GitHub App ID

# Option 1: Use private key file path
export GITHUB_APP_PRIVATE_KEY_PATH="/path/to/your-github-app.2025-01-11.private-key.pem"

# Option 2: Use private key content directly (alternative to path above)
# export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
# MIIEpAIBAAKCAQEA...
# ...
# -----END RSA PRIVATE KEY-----"

# Optional: GitHub webhook secret for signature validation
export WEBHOOK_SECRET="your-webhook-secret"

echo "Environment variables set for GitHub App authentication"
echo "GitHub App ID: $GITHUB_APP_ID"
echo "Private Key Path: $GITHUB_APP_PRIVATE_KEY_PATH"
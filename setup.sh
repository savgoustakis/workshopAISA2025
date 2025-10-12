#!/bin/bash
#
# Setup script for the workshop repository.
# This script configures all necessary GitHub Actions variables for the attendee.
#
set -e

# --- CONFIGURATION ---
# URL to the raw JSON file containing the workshop variables.
# As the host, you must provide this file.
VARIABLES_URL="https://raw.githubusercontent.com/SumitsWorkshopOrg/workshop/refs/heads/main/variables.json"
# --- END CONFIGURATION ---

echo "🚀 Starting workshop repository setup..."
echo ""

# --- Step 1: Check for Prerequisites ---
echo "🔎 Checking for required tools (gh and jq)..."
if ! command -v gh &> /dev/null; then
    echo "❌ Error: GitHub CLI ('gh') is not installed. Please install it to continue."
    echo "Installation instructions: https://github.com/cli/cli#installation"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "❌ Error: 'jq' is not installed. Please install it to continue."
    echo "On Debian/Ubuntu, run: sudo apt-get update && sudo apt-get install jq -y"
    exit 1
fi
echo "✅ All tools are present."
echo ""

# --- Step 2: Check GitHub Authentication ---
echo "🔐 GitHub authentication..."
gh auth login
echo "✅ Authenticated to GitHub as '$(gh api user -q .login)'."
echo ""

# --- Step 3: Identify Target Repository ---
TARGET_REPO=$(gh repo view --json owner,name --jq '.owner.login + "/" + .name')
if [ -z "$TARGET_REPO" ]; then
    echo "❌ Error: Could not determine the current GitHub repository."
    echo "Please make sure you are running this script from the root of your cloned workshop repository."
    exit 1
fi
echo "🎯 Configuring repository: $TARGET_REPO"
echo ""

# --- Step 4: Set Variables from Remote JSON ---
echo "⚙️ Setting up repository variables..."

# Download the variables and loop through them
curl -sSL "$VARIABLES_URL" | jq -c '.[]' | while read -r var_json; do
  VAR_NAME=$(echo "$var_json" | jq -r '.name')
  VAR_VALUE=$(echo "$var_json" | jq -r '.value')
  echo "   - Setting variable: ${VAR_NAME}"
  gh variable set "$VAR_NAME" --body "$VAR_VALUE" --repo "$TARGET_REPO"
done
echo "✅ Repository variables are set."
echo ""

echo "🎉 Workshop setup is complete!"

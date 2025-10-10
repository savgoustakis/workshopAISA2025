#!/bin/bash
set -e # Exit immediately if a command fails

# --- CONFIGURATION: Change these values before running ---
SOURCE_REPO="labuser2-cmyk/workshop"
TARGET_ORG="SumitsWorkshopOrg"
NEW_REPO_NAME="workshop-template" # Name for the new repo to be created
TAG_VERSION="v1.0"                 # The Git tag to create for this version
# --- END OF CONFIGURATION ---

# The full name of the new repository
TARGET_REPO="${TARGET_ORG}/${NEW_REPO_NAME}"

echo "### Step 1: Creating new repository ${TARGET_REPO} on GitHub..."
gh repo create "${TARGET_REPO}" --public --description "Cloned from ${SOURCE_REPO}"

echo "### Step 2: Cloning the source repository locally..."
# The repository name is the part after the '/'
SOURCE_REPO_DIR=$(basename "$SOURCE_REPO") 
git clone "https://github.com/${SOURCE_REPO}.git"
cd "${SOURCE_REPO_DIR}"

echo "### Step 3: Pushing the code to the new repository..."
git remote set-url origin "https://github.com/${TARGET_REPO}.git"
git push --all
git push --tags

echo "### Step 4: Tagging the initial workshop version as ${TAG_VERSION}..."
git tag -a "$TAG_VERSION" -m "Initial version for workshop: ${TAG_VERSION}"
git push origin "$TAG_VERSION"

echo "### Step 5: Copying variables from ${SOURCE_REPO} to ${TARGET_REPO}..."
gh variable list --repo "$SOURCE_REPO" --json name,value | \
jq -c '.[]' | \
while read -r variable_json; do
  # Extract the name and value of each variable
  VAR_NAME=$(echo "$variable_json" | jq -r '.name')
  VAR_VALUE=$(echo "$variable_json" | jq -r '.value')

  echo "Setting variable: '${VAR_NAME}' in ${TARGET_REPO}..."

  # Set the variable on the target repository
  gh variable set "$VAR_NAME" --body "$VAR_VALUE" --repo "${TARGET_REPO}"
done

echo "### Step 6: Cleaning up local clone..."
cd ..
rm -rf "${SOURCE_REPO_DIR}"

echo "✅ All done! New repository created and tagged. You can view it at:"
echo "https://github.com/${TARGET_REPO}/releases/tag/${TAG_VERSION}"

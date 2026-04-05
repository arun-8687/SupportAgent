#!/usr/bin/env bash
# map-files-to-wiki.sh — Maps changed source files to relevant wiki pages
# Usage: bash map-files-to-wiki.sh <changed_files.txt> <wiki_dir>
# Outputs JSON: { "pages": ["Page1.md", ...], "context_files": { "Page1.md": "content..." } }

set -euo pipefail

CHANGED_FILES="$1"
WIKI_DIR="$2"

declare -A PAGE_MAP
# Source directory -> wiki page mappings
PAGE_MAP["src/agents/"]="Agents.md"
PAGE_MAP["src/api/"]="API-Endpoints.md"
PAGE_MAP["src/engine/"]="Workflow-Pipeline.md"
PAGE_MAP["src/graph/"]="Workflow-Pipeline.md"
PAGE_MAP["src/integrations/"]="Architecture.md"
PAGE_MAP["src/intelligence/"]="Intelligence-Layer.md"
PAGE_MAP["src/observability/"]="Observability.md"
PAGE_MAP["src/providers/"]="Providers.md"
PAGE_MAP["src/publishers/"]="Architecture.md"
PAGE_MAP["src/runbooks/"]="Runbooks.md"
PAGE_MAP["src/services/"]="Architecture.md"
PAGE_MAP["src/storage/"]="Storage.md"
PAGE_MAP["src/tools/"]="Tools.md"
PAGE_MAP["config/"]="Configuration.md"
PAGE_MAP["infrastructure/"]="Deployment.md"
PAGE_MAP["Dockerfile"]="Deployment.md"
PAGE_MAP["docker-compose"]="Deployment.md"
PAGE_MAP["requirements.txt"]="Deployment.md"
PAGE_MAP["sdk/"]="SDK.md"
PAGE_MAP["tests/"]="Testing.md"
PAGE_MAP["scripts/"]="Deployment.md"
PAGE_MAP["functions/"]="API-Endpoints.md"
PAGE_MAP["docs/"]="Architecture.md"
PAGE_MAP[".env"]="Configuration.md"
PAGE_MAP["security"]="Security.md"

# Collect unique wiki pages that need updating
declare -A AFFECTED_PAGES

while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  matched=false
  for prefix in "${!PAGE_MAP[@]}"; do
    if [[ "$file" == *"$prefix"* ]]; then
      page="${PAGE_MAP[$prefix]}"
      AFFECTED_PAGES["$page"]=1
      matched=true
    fi
  done
  # If no specific mapping, flag Architecture.md as the catch-all
  if [[ "$matched" == "false" ]]; then
    AFFECTED_PAGES["Architecture.md"]=1
  fi
done < "$CHANGED_FILES"

# Always include Index.md and Log.md for bookkeeping
AFFECTED_PAGES["Log.md"]=1

# Build JSON output with page contents as context
echo "{"
echo "  \"pages\": ["
first=true
for page in "${!AFFECTED_PAGES[@]}"; do
  if [[ "$first" == "true" ]]; then
    first=false
  else
    echo ","
  fi
  printf "    \"%s\"" "$page"
done
echo ""
echo "  ],"
echo "  \"context\": {"
first=true
for page in "${!AFFECTED_PAGES[@]}"; do
  wiki_file="$WIKI_DIR/$page"
  if [[ -f "$wiki_file" ]]; then
    if [[ "$first" == "true" ]]; then
      first=false
    else
      echo ","
    fi
    # Escape content for JSON
    content=$(python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" < "$wiki_file")
    printf "    \"%s\": %s" "$page" "$content"
  fi
done
echo ""
echo "  }"
echo "}"

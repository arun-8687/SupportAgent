#!/usr/bin/env bash
# update-wiki-pages.sh — Uses GitHub Copilot CLI to update wiki pages based on PR diff
# Usage: bash update-wiki-pages.sh <diff_file> <mapping.json> <wiki_dir> <pr_title> <pr_number>

set -euo pipefail

DIFF_FILE="$1"
MAPPING_JSON="$2"
WIKI_DIR="$3"
PR_TITLE="$4"
PR_NUMBER="$5"

TODAY=$(date +%Y-%m-%d)

# Extract page list from mapping
PAGES=$(python3 -c "
import json, sys
with open('$MAPPING_JSON') as f:
    data = json.load(f)
for p in data['pages']:
    print(p)
")

# Truncate diff to avoid token limits (keep first 8000 chars)
DIFF_CONTENT=$(head -c 8000 "$DIFF_FILE")

echo "=== Pages to update: ==="
echo "$PAGES"
echo "========================"

# LLM call function: tries copilot -p, then falls back to GitHub Models API
call_llm() {
  local prompt="$1"
  local result=""

  # Try 1: copilot -p (Copilot CLI)
  if command -v copilot &>/dev/null; then
    result=$(echo "$prompt" | copilot -p 2>/dev/null) && { echo "$result"; return 0; }
    echo "WARN: copilot -p failed, trying fallback..." >&2
  fi

  # Try 2: GitHub Models REST API (uses GITHUB_TOKEN with models:read permission)
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    result=$(python3 -c "
import json, os, urllib.request, sys

prompt = sys.stdin.read()
body = json.dumps({
    'messages': [{'role': 'user', 'content': prompt}],
    'model': 'gpt-4o'
}).encode()

req = urllib.request.Request(
    'https://models.github.ai/inference/chat/completions',
    data=body,
    headers={
        'Authorization': f'Bearer {os.environ[\"GITHUB_TOKEN\"]}',
        'Content-Type': 'application/json'
    }
)

try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
        print(data['choices'][0]['message']['content'])
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" <<< "$prompt" 2>/dev/null) && { echo "$result"; return 0; }
    echo "WARN: GitHub Models API also failed" >&2
  fi

  return 1
}

# Process each affected page (except Log.md which we handle separately)
for page in $PAGES; do
  [[ "$page" == "Log.md" ]] && continue

  wiki_file="$WIKI_DIR/$page"
  [[ ! -f "$wiki_file" ]] && echo "SKIP: $page (not found)" && continue

  echo "--- Updating $page ---"

  CURRENT_CONTENT=$(cat "$wiki_file")

  PROMPT="You are updating a GitHub wiki page based on a code change from a merged pull request.

PR #${PR_NUMBER}: ${PR_TITLE}

Here is the diff (truncated):
\`\`\`
${DIFF_CONTENT}
\`\`\`

Here is the current wiki page ($page):
\`\`\`markdown
${CURRENT_CONTENT}
\`\`\`

Instructions:
- Update ONLY the sections of the wiki page that are affected by the diff.
- Keep all existing content that is still accurate.
- Add new sections if the diff introduces new components, endpoints, or features not yet documented.
- Remove or correct anything the diff makes obsolete.
- Preserve the page style: markdown headings, tables, wiki links with [[PageName]] syntax, code blocks.
- Do NOT add fluff, commentary, or meta-text. Just output the updated markdown.
- If the diff does not affect this page, output the page unchanged.

Output the complete updated wiki page markdown and nothing else:"

  UPDATED=$(call_llm "$PROMPT") || {
    echo "SKIP: $page (all LLM methods failed)"
    continue
  }

  # Validate we got meaningful output (at least 100 chars and contains a heading)
  if [[ ${#UPDATED} -gt 100 ]] && [[ "$UPDATED" == *"#"* ]]; then
    echo "$UPDATED" > "$wiki_file"
    echo "OK: $page updated (${#UPDATED} chars)"
  else
    echo "SKIP: $page (LLM output too short or invalid, ${#UPDATED} chars)"
  fi
done

# Update Log.md
echo "--- Updating Log.md ---"
LOG_FILE="$WIKI_DIR/Log.md"

# Build a list of updated pages for the log entry
UPDATED_LIST=""
for page in $PAGES; do
  [[ "$page" == "Log.md" ]] && continue
  pagename="${page%.md}"
  UPDATED_LIST="${UPDATED_LIST}\n- [[${pagename}]]"
done

# Generate a short summary of the diff using LLM
SUMMARY_PROMPT="Summarize this code diff in one sentence (max 20 words) for a changelog entry. No markdown, no quotes, just the sentence:
\`\`\`
${DIFF_CONTENT}
\`\`\`"

SUMMARY=$(call_llm "$SUMMARY_PROMPT" 2>/dev/null) || SUMMARY="Code changes from PR #${PR_NUMBER}"

# Clean summary (strip quotes, newlines)
SUMMARY=$(echo "$SUMMARY" | tr -d '\n' | sed 's/^"//;s/"$//' | head -c 120)

# Prepend new log entry after the --- separator
python3 << PYEOF
content = open('$LOG_FILE').read()
entry = """## [${TODAY}] PR #${PR_NUMBER} | ${PR_TITLE}

${SUMMARY}

**Pages updated:**${UPDATED_LIST}

---
"""
parts = content.split('---', 1)
if len(parts) == 2:
    new_content = parts[0] + '---\n\n' + entry + parts[1].lstrip('\n')
else:
    new_content = content + '\n\n---\n\n' + entry
with open('$LOG_FILE', 'w') as f:
    f.write(new_content)
PYEOF

echo "OK: Log.md updated with entry for PR #${PR_NUMBER}"
echo "=== Wiki update complete ==="

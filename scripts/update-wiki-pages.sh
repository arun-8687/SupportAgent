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

  # Use copilot CLI to generate the update
  UPDATED=$(echo "$PROMPT" | copilot -p 2>/dev/null) || {
    echo "WARN: copilot -p failed for $page, trying gh copilot..."
    UPDATED=$(echo "$PROMPT" | gh copilot -p 2>/dev/null) || {
      echo "WARN: gh copilot also failed for $page, skipping"
      continue
    }
  }

  # Validate we got meaningful output (at least 100 chars and starts with #)
  if [[ ${#UPDATED} -gt 100 ]] && [[ "$UPDATED" == *"#"* ]]; then
    echo "$UPDATED" > "$wiki_file"
    echo "OK: $page updated (${#UPDATED} chars)"
  else
    echo "SKIP: $page (copilot output too short or invalid, ${#UPDATED} chars)"
  fi
done

# Update Log.md
echo "--- Updating Log.md ---"
LOG_FILE="$WIKI_DIR/Log.md"

# Build a list of updated pages for the log entry
UPDATED_LIST=""
for page in $PAGES; do
  [[ "$page" == "Log.md" ]] && continue
  basename="${page%.md}"
  UPDATED_LIST="${UPDATED_LIST}\n- [[${basename}]]"
done

# Generate a short summary of the diff using copilot
SUMMARY_PROMPT="Summarize this code diff in one sentence (max 20 words) for a changelog entry. No markdown, no quotes, just the sentence:
\`\`\`
${DIFF_CONTENT}
\`\`\`"

SUMMARY=$(echo "$SUMMARY_PROMPT" | copilot -p 2>/dev/null) || \
SUMMARY=$(echo "$SUMMARY_PROMPT" | gh copilot -p 2>/dev/null) || \
SUMMARY="Code changes from PR #${PR_NUMBER}"

# Clean summary (strip quotes, newlines)
SUMMARY=$(echo "$SUMMARY" | tr -d '\n' | sed 's/^"//;s/"$//' | head -c 120)

# Prepend new log entry after the --- separator
LOG_ENTRY="## [${TODAY}] PR #${PR_NUMBER} | ${PR_TITLE}\n\n${SUMMARY}\n\n**Pages updated:**${UPDATED_LIST}\n\n---\n"

# Insert after the first --- line
python3 -c "
import sys
content = open('$LOG_FILE').read()
parts = content.split('---', 1)
if len(parts) == 2:
    new_content = parts[0] + '---\n\n' + '''${LOG_ENTRY}''' + parts[1].lstrip('\n')
else:
    new_content = content + '\n\n---\n\n' + '''${LOG_ENTRY}'''
with open('$LOG_FILE', 'w') as f:
    f.write(new_content)
"

echo "OK: Log.md updated with entry for PR #${PR_NUMBER}"
echo "=== Wiki update complete ==="

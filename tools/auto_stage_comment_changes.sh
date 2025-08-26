#!/bin/bash

# Auto-stage files that only have comment changes
# Uses -U50 context to catch most comment blocks

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🔍 Analyzing modified files for comment-only changes..."

# Get list of modified files (excluding deleted files)
modified_files=$(git diff --name-only --diff-filter=d)

if [ -z "$modified_files" ]; then
    echo "No modified files found."
    exit 0
fi

total_files=0
auto_staged=0
needs_review=0

# Function to check if a line looks like a comment
is_comment_line() {
    local line="$1"
    
    trimmed=$(echo "$line" | sed 's/^[[:space:]]*//')
    
    case "$trimmed" in
        # C-style single line comments
        "//"*) return 0 ;;
        # Block comment content (starts with *)
        "*"*) return 0 ;;
        # Documentation list items
        "-"*) return 0 ;;
        # Empty lines (often in comment blocks)
        "") return 0 ;;
        # Default: not a comment
        *) return 1 ;;
    esac
}

# Process each modified file
for file in $modified_files; do
    total_files=$((total_files + 1))
    echo -n "Analyzing $file... "
    
    diff_output=$(git diff -U50 "$file" 2>/dev/null || true)
    
    if [ -z "$diff_output" ]; then
        echo -e "${YELLOW}SKIP${NC} (no diff output)"
        continue
    fi
    
    in_block_comment=false
    all_comments=true
    
    while IFS= read -r line; do
        [[ "$line" =~ ^[+-]{3} ]] && continue
        
        if [[ "$line" =~ ^[[:space:]] ]]; then
            if [[ "$line" == *"/*"* ]]; then
                in_block_comment=true
            fi
            if [[ "$line" == *"*/"* ]]; then
                in_block_comment=false
            fi
        fi
        
        if [[ "$line" =~ ^[+-] ]]; then
            content="${line:1}"
            
            if ! (is_comment_line "$content" || $in_block_comment); then
                all_comments=false
                break
            fi
        fi
    done <<< "$diff_output"
    
    if [ "$all_comments" = true ]; then
        git add "$file"
        echo -e "${GREEN}AUTO-STAGED${NC} (comment-only changes)"
        auto_staged=$((auto_staged + 1))
    else
        echo -e "${RED}NEEDS REVIEW${NC} (contains code changes)"
        needs_review=$((needs_review + 1))
    fi
done

echo
echo "📊 Summary:"
echo -e "  Total files analyzed: $total_files"
echo -e "  ${GREEN}Auto-staged: $auto_staged${NC}"
echo -e "  ${RED}Need manual review: $needs_review${NC}"

if [ $auto_staged -gt 0 ]; then
    echo
    echo "✅ Auto-staged files are ready for commit!"
    echo "🔍 Please manually review the remaining $needs_review files."
fi

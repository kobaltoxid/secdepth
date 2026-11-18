#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
home_dir="${HOME:?HOME must be set}"
# Claude Code reads skills from CLAUDE_CONFIG_DIR when it is set, not ~/.claude.
claude_dir="${CLAUDE_CONFIG_DIR:-$home_dir/.claude}"
skill_dir="$repo_root/skills/secdepth"
agents=(codex claude)

if [[ $# -gt 1 ]]; then
    printf 'Usage: %s [all|codex|claude]\n' "$0" >&2
    exit 64
fi

case "${1:-all}" in
    all) ;;
    codex) agents=(codex) ;;
    claude) agents=(claude) ;;
    *)
        printf 'Usage: %s [all|codex|claude]\n' "$0" >&2
        exit 64
        ;;
esac

if [[ ! -f "$skill_dir/SKILL.md" ]]; then
    printf 'Secdepth skill not found at %s\n' "$skill_dir" >&2
    exit 1
fi

link_once() {
    local source="$1"
    local target="$2"
    mkdir -p "$(dirname "$target")"

    if [[ -L "$target" ]]; then
        if [[ "$(readlink "$target")" == "$source" ]]; then
            printf 'Already linked: %s\n' "$target"
            return
        fi
        printf 'Refusing to replace an existing symlink: %s\n' "$target" >&2
        exit 1
    fi
    if [[ -e "$target" ]]; then
        printf 'Refusing to replace an existing file or directory: %s\n' "$target" >&2
        exit 1
    fi

    ln -s "$source" "$target"
    printf 'Linked %s -> %s\n' "$target" "$source"
}

for agent in "${agents[@]}"; do
    if [[ "$agent" == codex ]]; then
        link_once "$skill_dir" "$home_dir/.agents/skills/secdepth"
    else
        link_once "$skill_dir" "$claude_dir/skills/secdepth"
    fi
done

printf 'Start a new agent session to load the Secdepth skill.\n'

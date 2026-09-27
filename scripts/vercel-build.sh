#!/usr/bin/env sh
# Vercel build step (vercel.json "buildCommand"). Python dependencies are
# already installed; this builds the static UI into ui/, which app.py serves.
# The API is app.py.
set -eu

# A variable added in Vercel with no value is set-but-empty, which jac.toml's
# ${LLM_MODEL:-...} fallback does not cover; byLLM then fails the build.
export LLM_MODEL="${LLM_MODEL:-gemini/gemini-2.5-flash}"

# jac-client bundles the UI with Bun.
command -v bun >/dev/null 2>&1 || npm install -g bun

# Cached console scripts can retain a shebang pointing at a previous build's
# absolute path. Run the module with the current environment's interpreter.
python -m jaclang build --client static main.jac

rm -rf ui
mkdir -p ui
cp -R .jac/client/dist/. ui/
rm -f ui/*.map
# Client-side routes: /console and /lab serve these copies (directory index)
# and React Router renders the matching page.
mkdir -p ui/console ui/lab
cp ui/index.html ui/console/index.html
cp ui/index.html ui/lab/index.html

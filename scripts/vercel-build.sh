#!/usr/bin/env sh
# Vercel build step (vercel.json "buildCommand"). Python dependencies are
# already installed; this builds the static UI into public/, which Vercel's
# CDN serves. The API is app.py.
set -eu

# jac-client bundles the UI with Bun.
command -v bun >/dev/null 2>&1 || npm install -g bun

jac build --client static main.jac

rm -rf public
mkdir -p public
cp -R .jac/client/dist/. public/
rm -f public/*.map
# Client-side routes: with "cleanUrls", /console and /lab serve these copies
# and React Router renders the matching page.
cp public/index.html public/console.html
cp public/index.html public/lab.html

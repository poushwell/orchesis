#!/bin/bash
# Deploy scanner to GitHub Pages via docs/ folder
echo "Deploying MCP Scanner to GitHub Pages..."
mkdir -p ../docs
cp index.html ../docs/
cp scanner-engine.js ../docs/
echo "Copied to docs/. Commit and push to deploy."
echo "Enable GitHub Pages: Settings -> Pages -> Source: main branch, /docs folder"


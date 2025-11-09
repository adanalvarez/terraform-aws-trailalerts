#!/usr/bin/env bash

# Script to build AWS Lambda Layer for Python dependencies from requirements.txt
set -euo pipefail

# Constants
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="python"
LAYER_ZIP="layer.zip"

# Helper functions
log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1"
    exit 1
}

# Change to script directory
cd "$SCRIPT_DIR"

# Validate requirements.txt exists
if [[ ! -f "requirements.txt" ]]; then
    log_error "requirements.txt not found"
fi

# Clean up previous builds
log_info "Cleaning up previous build artifacts..."
rm -rf "$PYTHON_DIR" "$LAYER_ZIP"

# Install dependencies
log_info "Installing Python packages..."
pip install --no-compile -r requirements.txt -t "$PYTHON_DIR/" || log_error "Failed to install dependencies"

# Normalize file timestamps for reproducible builds
log_info "Creating layer archive..."
find "$PYTHON_DIR" -exec touch -t 198001010000 {} +
find "$PYTHON_DIR" -type f | LC_ALL=C sort | zip -q -X -@ "$LAYER_ZIP"

# Copy the layer zip to build directory
BUILD_DIR="$SCRIPT_DIR/../../build"
log_info "Moving $LAYER_ZIP to $BUILD_DIR..."
mv "$LAYER_ZIP" "$BUILD_DIR/" || log_error "Failed to copy $LAYER_ZIP to $BUILD_DIR"

# Verify the zip file was created
if [[ -f "$BUILD_DIR/$LAYER_ZIP" ]]; then
    log_info "Successfully created Lambda layer: $BUILD_DIR/$LAYER_ZIP ($(du -h "$BUILD_DIR/$LAYER_ZIP" | cut -f1))"
else
    log_error "Failed to create layer archive"
fi
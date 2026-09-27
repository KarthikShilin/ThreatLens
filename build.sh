#!/bin/bash
set -e

echo ">>> Installing Python dependencies..."
pip install -r requirements.txt

echo ">>> Installing WhatWeb..."
apt-get update -qq && apt-get install -y -qq whatweb

echo ">>> Build complete!"

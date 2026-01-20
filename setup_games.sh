#!/bin/bash
set -e

# Configuration
PROJECT_DIR="$(pwd)"
PREFIX_DIR="$HOME/.win7games"
CACHE_DIR="$PROJECT_DIR/.cache"

# Ensure directories exist
mkdir -p "$PREFIX_DIR"
mkdir -p "$CACHE_DIR"

# Check Prerequisites
echo "Checking prerequisites..."
command -v wine >/dev/null 2>&1 || { echo >&2 "wine is required but not installed. Aborting."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo >&2 "python3 is required but not installed. Aborting."; exit 1; }
command -v ffmpeg >/dev/null 2>&1 || { echo >&2 "ffmpeg is required but not installed. Aborting."; exit 1; }
command -v 7z >/dev/null 2>&1 || { echo >&2 "7z is required but not installed. Please install 'p7zip-full' or equivalent. Aborting."; exit 1; }

# Setup Python Environment
if [ ! -d "$PROJECT_DIR/.venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$PROJECT_DIR/.venv"
fi
# Activate venv
source "$PROJECT_DIR/.venv/bin/activate"

# Install dependencies
echo "Installing Python dependencies..."
pip install --disable-pip-version-check --quiet lief pefile

# Setup WINEPREFIX
echo "Setting up Wine prefix at $PREFIX_DIR..."
export WINEPREFIX="$PREFIX_DIR"
export WINEARCH=win64
# Initialize prefix (quietly)
wineboot -u >/dev/null 2>&1 || true

echo "Running installer (Silent)..."
wine "$1" /S

# Run Patcher Script
echo "Patching games with localizations..."
cd "$PROJECT_DIR"
python3 patcher.py "$PREFIX_DIR"

# Patch Audio in CardGames.dll
echo "Patching audio in CardGames.dll..."
GAMES_ROOT="$PREFIX_DIR/drive_c/Program Files/Microsoft Games"
if [ ! -d "$GAMES_ROOT" ]; then
    GAMES_ROOT="$PREFIX_DIR/drive_c/Program Files (x86)/Microsoft Games"
fi

SOURCE_DLL="$GAMES_ROOT/Solitaire/CardGames.dll"
if [ ! -f "$SOURCE_DLL" ]; then
     # Try finding it elsewhere
     SOURCE_DLL=$(find "$GAMES_ROOT" -name "CardGames.dll" | head -n 1)
fi

if [ -f "$SOURCE_DLL" ]; then
    echo "Found CardGames.dll at $SOURCE_DLL"
    python3 dll_patcher.py "$SOURCE_DLL" "CardGames_fixed.dll"
    
    if [ -f "CardGames_fixed.dll" ]; then
        echo "Distributing patched DLL..."
        for d in "$GAMES_ROOT"/*; do
            if [ -d "$d" ] && [ -f "$d/CardGames.dll" ]; then
                cp "CardGames_fixed.dll" "$d/CardGames.dll"
                echo "Updated $d/CardGames.dll"
            fi
        done
        rm "CardGames_fixed.dll"
    else
        echo "Failed to create CardGames_fixed.dll"
    fi
else
    echo "CardGames.dll not found, skipping audio patch."
fi

# Create .desktop files
echo "Creating .desktop files..."
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"

# Find installed games to create shortcuts
# We look in Program Files inside the prefix
GAMES_ROOT="$PREFIX_DIR/drive_c/Program Files/Microsoft Games"
if [ ! -d "$GAMES_ROOT" ]; then
    GAMES_ROOT="$PREFIX_DIR/drive_c/Program Files (x86)/Microsoft Games"
fi

wine winemenubuilder

echo "Done! Games should be installed and patched."


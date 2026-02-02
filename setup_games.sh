#!/bin/bash
set -e

# Configuration
PROJECT_DIR=$( dirname "$0" )
PREFIX_DIR="$HOME/.win7games"
CACHE_DIR="$PROJECT_DIR/.cache"
PATCH_ONLY=false
INSTALLER_PATH=""

helptext="Usage: $0 [OPTIONS] <installer.exe>
   or: $0 -p|--patch [wine_prefix_directory]

Install and patch Windows 7 games for Wine compatibility.

OPTIONS:
    -h, --help              Show this help message and exit
    -p, --patch [PREFIX]    Patch-only mode. Skip installation and only apply patches
                            to an existing Wine prefix. If PREFIX is not specified,
                            defaults to ~/.win7games

EXAMPLES:
    # Install and patch games from installer
    $0 Win7GamesForWindows10and11.exe

    # Patch existing installation in default prefix
    $0 --patch

    # Patch existing installation in custom prefix
    $0 --patch /path/to/custom/prefix
"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
    	-h|--help)
		    echo "$helptext"
		    exit 0
            ;;
        -p|--patch)
            PATCH_ONLY=true
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                PREFIX_DIR="$2"
                shift 2
            else
                # Use default prefix if no argument provided
                PREFIX_DIR="$HOME/.win7games"
                shift
            fi
            ;;
        *)
            INSTALLER_PATH="$1"
            shift
            ;;
    esac
done

# Validate arguments
if [ "$PATCH_ONLY" = false ] && [ -z "$INSTALLER_PATH" ]; then
	echo "$helptext"
    exit 1
fi

if [ "$PATCH_ONLY" = true ] && [ ! -d "$PREFIX_DIR" ]; then
    echo "Error: Wine prefix directory does not exist: $PREFIX_DIR"
    exit 1
fi

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

# Setup WINEPREFIX and run installer (skip if patch-only mode)
if [ "$PATCH_ONLY" = false ]; then
    echo "Setting up Wine prefix at $PREFIX_DIR..."
    export WINEPREFIX="$PREFIX_DIR"
    export WINEARCH=win64
    # Initialize prefix (quietly)
    wineboot -u >/dev/null 2>&1 || true

    echo "Running installer (Silent)..."
    wine "$INSTALLER_PATH" /S
else
    echo "Patch-only mode: skipping installation..."
    export WINEPREFIX="$PREFIX_DIR"
fi

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

if [ "$PATCH_ONLY" = false ]; then
    echo "Creating .desktop files..."
    wine winemenubuilder
fi

rm -rf $PROJECT_DIR/.venv

echo "Done! Games patched successfully."

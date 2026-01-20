# Windows 7 Games, patched for Linux

<img width="800" alt="Screenshot From 2026-01-19 00-33-01" src="https://github.com/user-attachments/assets/5eda1b65-d54d-462e-8607-ce874c678b4e" />


Includes these games:
- Solitaire
- Spider Solitaire
- Minesweeper
- Hearts
- Chess
- FreeCell
- Mahjong
- Purble Place

## Installation

Dependencies:
- Wine 11
- ffmpeg
- 7z
- python3, and the following python packages
  - lief
  - pefile

1. Download a copy of the Windows 7 Games zip file, and extract it: https://win7games.com/

2. Clone this repo:

```bash
git clone https://github.com/donnybeelo/windows7GamesForLinux
```
3. Run the script, wit the executable as argument, e.g.:

```bash
./setup_games.sh "~/Downloads/Windows7Games_for_Windows_11_10_8.exe"
```

4. Should be good to go! If anything goes wrong, and you've followed the installation guide precisely,
[create an issue](https://github.com/donnybeelo/windows7GamesForLinux/issues).

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
- python3

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

## Troubleshooting

<details>
<summary><b>I'm not hearing any sound</b></summary>

Make sure you have all the gstreamer plugins installed, e.g. for Arch:
```bash
sudo pacman -S gst-plugins-base gst-plugins-good gst-plugins-bad gst-plugins-ugly
```
for Ubuntu:
```bash
sudo apt install gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly
```
In my testing, `gst-plugins-ugly` ended up being the package that got sound working
</details>
<details>
<summary><b>The game isn't running as well as I expected</b></summary>

Installing libav for gstreamer worked for me, e.g. for Arch:
```bash
sudo pacman -S gst-libav
```
For Ubuntu:
```bash
sudo apt install gstreamer1.0-libav
```
</details>
<details>
<summary><b>Something else / I tried one of the fixes above and it didn't help</b></summary>

Run the following in your terminal:
```bash
WINEPREFIX=$HOME/.win7games wine "$HOME/.win7games/drive_c/Program Files/Microsoft Games/Solitaire/Solitaire.exe"
```
Look at the logs, it will most likely indicate the issue. Worst case scenario, copy the logs into your favourite LLM and let it rip
</details>

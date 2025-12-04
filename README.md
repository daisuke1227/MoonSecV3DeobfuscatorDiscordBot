# MoonSecV3DeobfuscatorDiscordBot


### This is really bad and it doesnt have the same output as medal oracle or luadec but this is just a passion project that I really care about I hate obfuscated scripts so much since people cant learn how to make scripts obfuscation also hinders the user because they dont know what code there running it can be malicious and even steal your data like a lot of scripts ive deobfuscated obfuscated scripts can steal so much data you didnt even know about so deobfuscators like 25ms threaded and mine are very important in more ways then just skidding


A Discord bot designed to automate the deobfuscation of Lua scripts using MoonSec V3.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8+**: [Download Python](https://www.python.org/downloads/)
- **MoonSec Deobfuscator**: You need the executable for the deobfuscator.

## Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/daisuke1227/MoonSecV3DeobfuscatorDiscordBot.git
    cd MoonSecV3DeobfuscatorDiscordBot
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
3. **Install Moonsec Deobfuscator**
    ```bash
    git clone https://github.com/tupsutumppu/MoonsecDeobfuscator.git
    cd MoonsecDeobfuscator
    dotnet build -c Release
    ```

## Configuration

1.  **Create a `.env` file**
    Copy the `example.env` (if available) or create a new `.env` file in the root directory.

2.  **Configure Environment Variables**
    Add the following lines to your `.env` file, replacing the placeholders with your actual paths and tokens:

    ```env
    # Your Discord Bot Token
    DISCORD_TOKEN=your_discord_bot_token_here

    # Path to the MoonSec Deobfuscator Executable
    MOON_EXECUTABLE=C:\Path\To\MoonsecDeobfuscator.exe

    # Name of the decompression script (usually decom.lua)
    DECOM_SCRIPT=decom.lua
    ```

## Usage

1.  **Run the Bot**
    ```bash
    python bot.py
    ```

2.  **Using the Bot in Discord**
    - **Upload a File**: Simply type in ".deobf the`.lua` or `.txt` file" into a channel where the bot has access. The bot will automatically download, process, and reply with the deobfuscated file.
    - **Send a Link**: Type in .deobf and the pasted link to the `.lua` or `.txt` file. The bot will download it and process it.

## Troubleshooting

- **Moon Error**: If you see a "Moon Error", check that the `MOON_EXECUTABLE` path in your `.env` file is correct and that the deobfuscator is working independently.
- **Decompiled file missing**: This usually means the `DECOM_SCRIPT` failed or the Lua binary path is incorrect. Check your console output for more details.

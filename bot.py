import discord
from discord.ext import commands
import subprocess
import os
import random
import string
import aiohttp
import asyncio
import platform
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
MOON_EXECUTABLE = os.getenv("MOON_EXECUTABLE")
DECOM_SCRIPT = os.getenv("DECOM_SCRIPT")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

def get_lua_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    system = platform.system()
    
    if system == "Windows":
        return os.path.join(current_dir, "bin", "lua5.1.exe")
    elif system == "Linux":
        path = os.path.join(current_dir, "bin", "lua5.1")
        if os.path.exists(path):
            os.chmod(path, 0o755)
        return path
    else:
        return "lua5.1"

LUA_BIN = get_lua_path()

def generate_random_filename(length=16, extension=""):
    letters = string.ascii_lowercase + string.digits
    name = ''.join(random.choice(letters) for i in range(length))
    return f"{name}{extension}"

async def safe_send(ctx, content, max_length=1900):
    if len(content) <= max_length:
        await ctx.send(content)
    else:
        truncated = content[:max_length] + "\n...\n[Output truncated]"
        await ctx.send(truncated)

async def download_file(url, filename):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status == 200:
                with open(filename, 'wb') as f:
                    f.write(await resp.read())
                return True
    return False

async def process_pipeline(ctx, input_filepath):
    output_luac_name = generate_random_filename(16, ".luac")
    output_luac_path = os.path.abspath(output_luac_name)
    expected_decompiled_path = output_luac_path.replace(".luac", "_decompiled.lua")
    
    status_msg = await ctx.send(f"Processing... \nInput: {os.path.basename(input_filepath)}\nTarget: {os.path.basename(expected_decompiled_path)}")

    open_file_handles = []

    try:
        my_env = os.environ.copy()
        if platform.system() == "Linux":
            my_env["LD_LIBRARY_PATH"] = "/usr/lib:/usr/local/lib"

        cmd_moon = [MOON_EXECUTABLE, "-dev", "-i", input_filepath, "-o", output_luac_path]
        
        process_moon = subprocess.run(
            cmd_moon, 
            capture_output=True, 
            text=True,
            env=my_env
        )

        if process_moon.returncode != 0:
            error_output = process_moon.stderr or process_moon.stdout
            await safe_send(ctx, f"Moon Error:\n```{error_output}```")
            return

        cmd_decom = [LUA_BIN, DECOM_SCRIPT, output_luac_path, expected_decompiled_path]
        
        process_decom = subprocess.run(
            cmd_decom, 
            capture_output=True, 
            text=True
        )

        files_to_send = []
        
        if os.path.exists(output_luac_path):
            f1 = open(output_luac_path, 'rb')
            open_file_handles.append(f1)
            files_to_send.append(discord.File(f1, filename=output_luac_name))
        
        if os.path.exists(expected_decompiled_path):
            f2 = open(expected_decompiled_path, 'rb')
            open_file_handles.append(f2)
            files_to_send.append(discord.File(f2, filename=os.path.basename(expected_decompiled_path)))
        else:
            await safe_send(ctx, f"Decompiled file missing. Lua Output:\n```{process_decom.stdout}```")

        if files_to_send:
            await ctx.send(content=f"Done.\nGenerated: {os.path.basename(expected_decompiled_path)}", files=files_to_send)
        else:
            await ctx.send("Processes ran, but no output files were found.")

    except Exception as e:
        await ctx.send(f"System Error: {str(e)}")

    finally:
        for f in open_file_handles:
            f.close()

        try:
            if os.path.exists(input_filepath): 
                os.remove(input_filepath)
            if os.path.exists(output_luac_path): 
                os.remove(output_luac_path)
            if os.path.exists(expected_decompiled_path): 
                os.remove(expected_decompiled_path)
            
            await status_msg.delete()
        except Exception as e:
            print(f"Cleanup error: {e}")

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    print(f'Detected OS: {platform.system()}')
    print(f'Lua Binary Path: {LUA_BIN}')

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    if message.attachments:
        for attachment in message.attachments:
            if attachment.filename.endswith(('.lua', '.txt')):
                input_filename = generate_random_filename(8, ".lua")
                await attachment.save(input_filename)
                await process_pipeline(message.channel, input_filename)
                return 

    content = message.content.strip()
    if content.startswith("http") and content.endswith(('.lua', '.txt')):
         input_filename = generate_random_filename(8, ".lua")
         if await download_file(content, input_filename):
             await process_pipeline(message.channel, input_filename)
         else:
             await message.channel.send("Could not download file from link.")

    await bot.process_commands(message)

bot.run(TOKEN)
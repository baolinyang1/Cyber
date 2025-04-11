import os
import json
import hashlib
import mimetypes
import sys
import zlib
from datetime import datetime
from os import MFD_ALLOW_SEALING
from pathlib import Path
import subprocess
import ppdeep
import io
import fuzzyhashlib


# #################################################################3

input_file = "xxxxxxxxxxxxxxx"

# CHECK IF PATH EXISTS
if os.path.exists("file.txt"):
    print("File exists")
    pass
else:
    print("File doesn't exist")

# CHECK IF FILE EXISTS
p = Path("file.txt")

# CHECK IF FILE IS A FILE AND NOT A SPECIAL FILE
if p.exists():
    #check if it's regular file
    if p.is_file():
        print("File exists and it is a file")
    else:
        print("It is not a file")
else:
    print("File doesn't exist")

Found_tools = dict()
# CHECK IF SYSTEM HAS
Tools = ['md5sum',"sha1sum","sha224sum","sha256sum","sha384sum","sha512sum","rhash","openssl","ssdeep","exiftool"]
def CheckSysHash(tools):
    for hash in tools:
        try:
            process = subprocess.run(["which", hash], capture_output=True, text=True)
            if process.returncode == 0:
                print(f"{hash} found")
                res = "found"
            else:
                print(f"{hash} not found")
                res = "not_found"
            process = None
        except Exception as e:
            print(f"{hash} failed to find")

        Found_tools[hash] = res
    hash = None
CheckSysHash(Tools)
print(Found_tools)

# CHECK IF PYTHON LIBRARY CAN HASH
available_hashes_dict = {}
Hashes2 = ["md5","sha1","sha224","sha256","sha384","sha512","sha3_224","sha3_256","sha3_384","sha3_512","blake2s","blake2b","shake_128","shake_256"]
available_hashes = []
for hash_name in Hashes2:
    try:
        hash_object = hashlib.new(hash_name)
        available_hashes.append(hash_name)
        available_hashes_dict[hash_name] = hash_object
        hash_object = None
    except Exception as e:
        pass

hash_name = None
print("Available python hashing algorithms:", available_hashes)
print("Available python hashing algorithm dict:", available_hashes_dict)


hash_types = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2s", "blake2b", "shake_128", "shake_256",
]

hash_commands = {
    "md5": "md5sum",
    "sha1": "sha1sum",
    "sha224": "sha224sum",
    "sha256": "sha256sum",
    "sha384": "sha384sum",
    "sha512": "sha512sum",
}


result_hashes = {}

with io.open(p, "rb") as f:
        while chunk := f.read(4096):
            result_hashes["sdhash"] = fuzzyhashlib.sdhash(chunk)

fileszie = os.path.getsize(p)
if fileszie >= 4096:
    #just a note here, because the file is so small, othewise the ppdeep can read the file bu chunks
    with io.open(p, "rb") as f:
        while chunk := f.read(4096):
            result_hashes["ssdeep"] = ppdeep.hash(chunk)
if len(available_hashes_dict) > 1 :
    print("Available hashes dict has more than one python hash algorithm")
    for algo in hash_types:
        # 1.use Python hashlib if supported
        if algo in list(available_hashes_dict.keys()):
            try:
                h = available_hashes_dict[algo]
                with io.open(p, "rb") as f:
                    while chunk := f.read(4096):
                        h.update(chunk)
                result_hashes[algo] = h.hexdigest(32) if algo.startswith("shake") else h.hexdigest()
                
            except Exception as e:
                print(f"Error: {e}")
 
    #system tools handle the left
    for rest in hash_types:
        if rest in result_hashes:
            continue  # Skip already processed hashes
        cmd_name = hash_commands.get(rest)
        if cmd_name and Found_tools.get(cmd_name) == "found":
            try:
                output = subprocess.check_output([cmd_name, str(p)], text=True)
                result_hashes[rest] = output.split()[0]
            except Exception as e:
                result_hashes[rest] = ""
                continue
        else:
            result_hashes[rest] = ""
else:
    print("Python hash support is limited — using system tools first")

    # 1. Try system tools first
    for algo in hash_types:
        cmd_name = hash_commands.get(algo)
        if cmd_name and Found_tools.get(cmd_name) == "found":
            try:
                output = subprocess.check_output([cmd_name, str(p)], text=True)
                result_hashes[algo] = output.split()[0]
            except Exception as e:
                result_hashes[algo] = ""

    # 2. Try Python for remaining ones
    for algo in hash_types:
        if algo in result_hashes:
            continue  # Already handled
        if algo in available_hashes_dict:
            try:
                h = available_hashes_dict[algo]
                with io.open(p, "rb") as f:
                    while chunk := f.read(4096):
                        h.update(chunk)
                result_hashes[algo] = h.hexdigest(32) if algo.startswith("shake") else h.hexdigest()
            except Exception as e:
                result_hashes[algo] = ""
        else:
            result_hashes[algo] = ""

print("\n# FINAL RESULT")
print(json.dumps(result_hashes, indent=4))




#hashlib_calls = list(dir(hashlib))
"""
[
 'blake2b', 
 'blake2s', 
 'md5', 
 'pbkdf2_hmac', 
 'scrypt', 
 'sha1', 
 'sha224', 
 'sha256', 
 'sha384', 
 'sha3_224', 
 'sha3_256', 
 'sha3_384', 
 'sha3_512', 
 'sha512', 
 'shake_128', 
 'shake_256'
 ]
"""
#print(hashlib_calls)
# if "md5" in hashlib_calls:
#     "md5": hashlib.md5(),
#     "sha1": hashlib.sha1(),
#     "sha224": hashlib.sha224(),
#     "sha256": hashlib.sha256(),
#     "sha384": hashlib.sha384(),
#     "sha512": hashlib.sha512(),
#     "sha3_224": hashlib.sha3_224(),
#     "sha3_256": hashlib.sha3_256(),
#     "sha3_384": hashlib.sha3_384(),
#     "sha3_512": hashlib.sha3_512(),
#     "blake2s": hashlib.blake2s(),
#     "blake2b": hashlib.blake2s(),
#     "shake_128": hashlib.shake_128(),
#     "shake_256": hashlib.shake_256(),



# sys.exit()
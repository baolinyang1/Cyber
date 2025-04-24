#This script is used to combine all the hashes, file metadata and the trid 
# First part is Check.py
import os
import json
import hashlib
import mimetypes
from datetime import datetime
from pathlib import Path
import subprocess
import ppdeep
import io
import tlsh
from magika import Magika

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
Tools = ['md5sum',"sha1sum","sha224sum","sha256sum","sha384sum","sha512sum","rhash","openssl","ssdeep","exiftool", "sdhash"]
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
# print("Available python hashing algorithms:", available_hashes)
# print("Available python hashing algorithm dict:", available_hashes_dict)


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


Results = {}

fileszie = os.path.getsize(p)
#for ssdeep
if fileszie >= 4096:
    #just a note here, because the file is so small, othewise the ppdeep can read the file by chunks
    with io.open(p, "rb") as f:
        while chunk := f.read(4096):
            Results["ssdeep"] = ppdeep.hash(chunk)
else:
    Results["ssdeep"] = "file is less than 4kb"

#for TLSH
if fileszie >= 256:
    with io.open(p, "rb") as f:
        while chunk := f.read(4096):
            Results["TLSH"] = tlsh.hash(chunk)
else:
    Results["TLSH"] = "file is less than 256 bytes"

#For magika
m = Magika()
res = m.identify_path(p)

Results["Magika-lable"] = res.output.label
Results["Magika-mime_type"] = res.output.mime_type
Results["Magika-group"] = res.output.group
Results["Magika-description"] = res.output.description
Results["Magika-extensions"] = res.output.extensions
Results["Magika-isText"] = res.output.is_text

print(res)
if len(available_hashes_dict) > 1 :
    #print("Available hashes dict has more than one python hash algorithm")
    for algo in hash_types:
        # 1.use Python hashlib if supported
        if algo in list(available_hashes_dict.keys()):
            try:
                h = available_hashes_dict[algo]
                with io.open(p, "rb") as f:
                    while chunk := f.read(4096):
                        h.update(chunk)
                Results[algo] = h.hexdigest(32) if algo.startswith("shake") else h.hexdigest()
                
            except Exception as e:
                print(f"Error: {e}")
 
    #system tools handle the left
    for rest in hash_types:
        if rest in Results:
            continue  # Skip already processed hashes
        cmd_name = hash_commands.get(rest)
        if cmd_name and Found_tools.get(cmd_name) == "found":
            try:
                output = subprocess.check_output([cmd_name, str(p)], text=True)
                Results[rest] = output.split()[0]
            except Exception as e:
                Results[rest] = ""
                continue
        else:
            Results[rest] = ""
else:
    print("Python hash support is limited — using system tools first")

    # 1. Try system tools first
    for algo in hash_types:
        cmd_name = hash_commands.get(algo)
        if cmd_name and Found_tools.get(cmd_name) == "found":
            try:
                output = subprocess.check_output([cmd_name, str(p)], text=True)
                Results[algo] = output.split()[0]
            except Exception as e:
                Results[algo] = ""

    # 2. Try Python for remaining ones
    for algo in hash_types:
        if algo in Results:
            continue  # Already handled
        if algo in available_hashes_dict:
            try:
                h = available_hashes_dict[algo]
                with io.open(p, "rb") as f:
                    while chunk := f.read(4096):
                        h.update(chunk)
                Results[algo] = h.hexdigest(32) if algo.startswith("shake") else h.hexdigest()
            except Exception as e:
                Results[algo] = ""
        else:
            Results[algo] = ""

#normaly the first 8 bytes
def get_file_magic(file_path):
    try:
        #subprocess is a module used to run external shell commands from within Python
        #file is Unix command that checks file types using magic numbers, -b means breif mode, decode mode is text(string)
        return subprocess.check_output(["file", "-b", file_path], text=True).strip()
    except Exception as e:
        return f"Failed to read file magic: {str(e)}"

def get_file_info(file_path):
    #Uses the pathlib module to create a Path object.
    p = Path(file_path)
    file_stats = p.stat()

    #call or fallback(return None)
    mime_type, mime_encoding = mimetypes.guess_type(file_path)
    mime_type = mime_type or "unknown"
    mime_encoding = mime_encoding or "binary"

    file_magic = get_file_magic(file_path)

    return {
        "path": str(p.resolve()),
        #returns the base name of the file without the extension
        "file_name": p.stem,
        #first get the last suffix, then from the left, remove the first .
        "file_extension": p.suffix.lstrip('.'),
        "Size": file_stats.st_size,
        "Modify_date": datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
        "file_magic": file_magic,
        "file_mime_type": mime_type,
        "file_mime_encoding": mime_encoding
    }


# Add file metadata
file_info = get_file_info(str(p))
Results.update(file_info)

# Add TrID result
try:
    trid_result = subprocess.run(
        ["./trid", str(p)],
        env={**os.environ, "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding='utf-8',
        errors='ignore'
    )
    lines = trid_result.stdout.splitlines()
    capture = False
    trid_matches = []

    for line in lines:
        if line.strip().startswith("Collecting data from file:"):
            capture = True
            continue
        if capture:
            if line.strip() == "":
                break
            if not line.startswith("Trid") and not line.startswith("Definitions") and not line.startswith("Analyzing"):
                trid_matches.append(line.strip())

    if not trid_matches:
        for line in lines:
            if "Unknown!" in line:
                trid_matches.append("Unknown!")
                break

    Results["trid"] = trid_matches

except Exception as e:
    Results["trid"] = [f"Failed to run trid: {e}"]

# Final print
print("\n# FINAL RESULT WITH METADATA + HASHES + TRID")
print(json.dumps(Results, indent=4))

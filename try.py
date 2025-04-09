# import os
# import json
# import hashlib
# import mimetypes
# import zlib
# from datetime import datetime
# from pathlib import Path
# import subprocess

# def compute_hashes(file_path):
#     hash_algs = {
#         #from the hashlib module
#         "md5": hashlib.md5(),
#         "sha1": hashlib.sha1(),
#         "sha224": hashlib.sha224(),
#         "sha256": hashlib.sha256(),
#         "sha384": hashlib.sha384(),
#         "sha512": hashlib.sha512(),
#         "sha3_224": hashlib.sha3_224(),
#         "sha3_256": hashlib.sha3_256(),
#         "sha3_384": hashlib.sha3_384(),
#         "sha3_512": hashlib.sha3_512(),
#         "blake2s": hashlib.blake2s(),
#         "blake2b": hashlib.blake2b(),
#         "shake_128": hashlib.shake_128(),
#         "shake_256": hashlib.shake_256(),
#     }

#     with open(file_path, "rb") as f:
#         content = f.read()

#     result = {} 
#     for name, hasher in hash_algs.items():
#         if name.startswith("shake"):
#             result[name.upper()] = hasher.copy().update(content) or hasher.hexdigest(32)
#         else:
#             hasher.update(content)
#             result[name] = hasher.hexdigest()

#     result["crc32"] = format(zlib.crc32(content) & 0xFFFFFFFF, '08x')
#     return result

# def get_file_info(file_path):
#     p = Path(file_path)
#     file_stats = p.stat()

#     mime_type, mime_encoding = mimetypes.guess_type(file_path)
#     mime_type = mime_type or "unknown"
#     mime_encoding = mime_encoding or "binary"

#     try:
#         file_magic = subprocess.check_output(["file", "-b", file_path], text=True).strip()
#     except Exception:
#         file_magic = f"Cannot determine file type on this OS"

#     return {
#         "path": str(p.resolve()),
#         "file_name": p.stem,
#         "file_extension": p.suffix.lstrip('.'),
#         "Size": file_stats.st_size,
#         "Modify_date": datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
#         "file_magic": file_magic,
#         "file_mime_type": mime_type,
#         "file_mime_encoding": mime_encoding
#     }

# def generate_file_report(file_path, output_json="file_report.json"):
#     info = get_file_info(file_path)
#     hashes = compute_hashes(file_path)

#     result = {
#         "file_path": info["path"],
#         "path": info["path"],
#         "file_name": info["file_name"],
#         "file_extension": info["file_extension"],
#         "Size": info["Size"],
#         "Modify_date": info["Modify_date"],
#         "file_magic": info["file_magic"],
#         "file_mime_type": info["file_mime_type"],
#         "file_mime_encoding": info["file_mime_encoding"],
#         **hashes,
#         "ssdeep": "",
#         "exif": {}
#     }

#     with open(output_json, "w") as f:
#         json.dump(result, f, indent=4)

#     return result

# if __name__ == "__main__":
#     import sys
#     if len(sys.argv) != 2:
#         print("Usage: python try.py <file_path>")
#     else:
#         file_path = sys.argv[1]
#         if not os.path.exists(file_path):
#             print(f"Error: file '{file_path}' does not exist.")
#         else:
#             report = generate_file_report(file_path)
#             print("# FINAL RESULT\n")
#             print(json.dumps(report, indent=4))

import os
import json
import hashlib
import mimetypes
import zlib
from datetime import datetime
from pathlib import Path
import subprocess

def compute_hashes(file_path):
    hash_algs = {
        #these are from the hash library
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha224": hashlib.sha224(),
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
        "sha3_224": hashlib.sha3_224(),
        "sha3_256": hashlib.sha3_256(),
        "sha3_384": hashlib.sha3_384(),
        "sha3_512": hashlib.sha3_512(),
        "blake2s": hashlib.blake2s(),
        "blake2b": hashlib.blake2b(),
        "shake_128": hashlib.shake_128(),
        "shake_256": hashlib.shake_256(),
    }

    #read the file as raw binary bytes, coz hash algorithm only works on binary not text
    #with ... as can ensure open properly the file and auto close it
    #store the read() results into content variable
    #f = open(file_path, "rb")
    with open(file_path, "rb") as f:
        content = f.read()
    #store the result in dictionary 
    result = {} 
    #loop through each key and value in the dictionary, item() method!
    for name, hasher in hash_algs.items():
        #haveto specify the length of this one
        if name.startswith("shake"):
            #hasher is the value field in that dict
            #It feeds binary data into a hash object, allowing it to calculate the hash based on that data.
            hasher.update(content)
            #upper case name to distinction
            #hexdigest() returns a hex string 
            # this is the way to put stuff into dict
            result[name.upper()] = hasher.hexdigest(32)
        else:
            hasher.update(content)
            result[name] = hasher.hexdigest()
    #calculates the CRC32 checksum of the binary content, & after to make sure Treated as an unsigned 32-bit integer, 
    # Converts the integer to an 8-digit hexadecimal string
    result["crc32"] = format(zlib.crc32(content) & 0xFFFFFFFF, '08x')
    return result

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

def generate_file_report(file_path, output_json="file_report.json"):
    #get two dicts
    info = get_file_info(file_path)
    hashes = compute_hashes(file_path)

    result = {
        "file_path": info["path"],
        #can do some realtive path here
        "path": info["path"],
        "file_name": info["file_name"],
        "file_extension": info["file_extension"],
        "Size": info["Size"],
        "Modify_date": info["Modify_date"],
        "file_magic": info["file_magic"],
        "file_mime_type": info["file_mime_type"],
        "file_mime_encoding": info["file_mime_encoding"],
        **hashes,
    }

    with open(output_json, "w") as f:
        # a tab indentation
        json.dump(result, f, indent=4)

    return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python try.py <file_path>")
    else:
        file_path = sys.argv[1]
        if not os.path.exists(file_path):
            print(f"Error: file '{file_path}' does not exist.")
        else:
            report = generate_file_report(file_path)
            print("# FINAL RESULT\n")
            print(json.dumps(report, indent=4))

import argparse
import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

parser = argparse.ArgumentParser(description='Encrypt or decrypt files using XOR encryption.')
parser.add_argument('-i','--input', required=True, help='Input file name')
parser.add_argument('-p','--path', help='File path')
parser.add_argument('-o','--output', required=True, help='Output file name')
parser.add_argument('-k','--key', required=True, help='Encryption key')
parser.add_argument('-v','--vkn', action='store_true', help='Export as .vkn file')
args = parser.parse_args()

if os.path.isfile(args.input):
    input_file = args.input
    output_file = args.output
    key = args.key
    ekey = key.encode()
    header = b'ENCRYPTED'
    vkn_header = b'VKNFILE'
    if args.path:
        output_file = os.path.join(args.path, output_file)
    if not args.vkn:
        with open(input_file, 'rb') as file:
            all_bytes = file.read()
        with open(output_file, 'wb') as file:
            if all_bytes[:len(header)] != header:
                file.write(header)
                file.write(hash)
                for i in range(len(all_bytes)):
                    file.write(bytes([all_bytes[i] ^ ekey[i % len(key)]]))
                print(f"File encrypted successfully and saved as {output_file}")
            else:
                hash_in_file = all_bytes[len(header):len(header)+len(hash)]
                if hash_in_file == hash:
                    for i in range(len(all_bytes)-len(header)-len(hash)):
                        file.write(bytes([all_bytes[i+len(header)+len(hash)] ^ ekey[i % len(key)]]))
                    print(f"File decrypted successfully and saved as {output_file}")
                else:
                    print("Error: Hash mismatch. File may be corrupted or key is incorrect.")
                    exit()
    else:
        with open(input_file, 'rb') as file:
            all_bytes = file.read()
        if all_bytes[:len(vkn_header)] == vkn_header:
            salt = all_bytes[len(vkn_header):len(vkn_header)+16]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            vkey = kdf.derive(ekey)
            hash = hashlib.sha256(key.encode()).digest()
            hash_in_file = all_bytes[len(vkn_header)+len(salt):len(vkn_header)+len(salt)+len(hash)]
            if hash_in_file == hash:
                with open(output_file, 'wb') as file:
                    for i in range(len(all_bytes)-len(vkn_header)-len(salt)-len(hash)):
                        file.write(bytes([all_bytes[i+len(vkn_header)+len(salt)+len(hash)] ^ vkey[i % len(vkey)]]))
                print(f"VKN File decrypted successfully and saved as {output_file}")
            else:
                print("Error: Hash mismatch. File may be corrupted or key is incorrect.")
                exit()
        else:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            vkey = kdf.derive(ekey)
            hash = hashlib.sha256(key.encode()).digest()
            output_file = os.path.splitext(output_file)[0] + '.vkn'
            with open(output_file, 'wb') as file:
                file.write(vkn_header)
                file.write(salt)
                file.write(hash)
                for i in range(len(all_bytes)):
                    file.write(bytes([all_bytes[i] ^ vkey[i % len(vkey)]]))     
            print(f"VKN File encrypted successfully and saved as {output_file}")
else:
    print("Error: Input file does not exist.")
    exit()
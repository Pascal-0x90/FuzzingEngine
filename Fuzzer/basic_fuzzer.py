#!/usr/bin/env python3

import random
import string
import gc
import time
import os
from subprocess import run, PIPE
from signal import signal, SIGINT
import sys

LASTFILE = ""

def handler(signal_received, frame):
    # Handle any cleanup here
    print(f"[-] Last file ran: {LASTFILE}")
    sys.exit(0)

def gen_rand(seed: float = time.time(), max_len: int = 250):
    """Generate a random string to be used as input."""
    # Set Char space in bytes
    char_pot = [i.encode() for i in string.printable]
    # Grab random number
    fuzz_len = random.randint(0, max_len + 1)
    # Generate bytestring
    fuzz_str = b""
    for idx in range(0,fuzz_len):
        fuzz_str += char_pot[random.randint(0,len(char_pot)-1)]
    return fuzz_str

def gen_input_file(name: str, str_len: int):
    """Generate set of fuzz files which will be fed."""
    global LASTFILE
    # Generate a fuzz str
    fuzz_str = gen_rand(max_len=str_len)
    # Create folder and set files
    if not os.path.exists("./input"):
        os.mkdir("./input")
        print("[+] Directory created.")
    else:
        pass
    with open("./input/fuzz_" + name, "wb") as fp:
        fp.write(fuzz_str)
    LASTFILE = name
    return name

def fuzzer(binary: str, size: int = 250):
    """The main fuzzer runner."""
    if "./" not in binary and binary[0] != "/":
        binary = "./" + binary
    # Start signal
    signal(SIGINT, handler)
    print("[+] STARTING FUZZER...")
    while True:
        name = gen_input_file(''.join([string.ascii_letters[random.randint(i,len(string.ascii_letters)-1)] for i in range(0,6)]), size)
        fuzz_in = open("./input/fuzz_" + name ,"rb").read().decode()
        proc = run([binary], stdout=PIPE, input=fuzz_in, encoding='ascii')
        if proc.returncode != 0:
            print("="*20)
            print(f"CRASH FROM: ./input/fuzz_{name}")
            return 0
        os.remove("./input/fuzz_" + name)
        name = None

if __name__ == "__main__":
    sys.exit(fuzzer(sys.argv[1]))

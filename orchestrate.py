#!/usr/bin/env python3

import subprocess
import sys
import os
from signal import signal, SIGINT

def murder_gdb():
    data = subprocess.check_output(["pidof","gdb"]).decode()[:-1]
    subprocess.check_output(["kill",data])

def start(binary):
    data = []
    try:
        proc = subprocess.Popen(f"gdb -x gdbinit {binary}", shell=True, stdout=subprocess.PIPE, start_new_session=True)
        while proc.poll() is None:
            data.append(proc.stdout.readline())
        crash = -1
        for d in data:
            if b"SIGSEGV" in d:
                crash += 1
        print(f"{crash} successful crashes!")
    except KeyboardInterrupt:
        murder_gdb()
        print("\n==========Keyboard interrupt!==========")

def main():
    binary = sys.argv[1]
    in_dir = sys.argv[2]
    crash_dir = sys.argv[3]

    # Setup gdbinit
    base = ""
    with open("util/gdbinit_base","r") as fp:
        base = fp.read()
    with open("gdbinit","w") as fp:
        fp.write(f'set $indir="{in_dir}"\n')
        fp.write(f'set $crash="{crash_dir}"\n')
        fp.write(base)
    start(binary)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

from __future__ import print_function

# Standard Python Libraries
import os
import queue
from signal import SIGINT, signal
import sys
from typing import List

# Third-Party Libraries
from capstone import *
from elftools.elf.elffile import ELFFile
import gdb

# Internal Libraries
from fuzzLib import Fuzzer

# Global Variables
CURRENT_ADDR = 0
PREV_ADDR = 0
SHARED_MEM = [0] * (64 * 1024)  # ~6 mb
GLOBAL_MAPPINGS: List[list] = []
CURRENT = ""  # Our current File
INPUT_DIR = ""  # input directory to hold candidates
CRASH_DIR = ""  # Crash directory to hold heroes

# Aux lib
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def handler(signal_received, frame):
    # Handle any cleanup here
    print(f"[-] Last file ran: ME")
    gdb.execute("quit", to_string=True)


def grab_jmps(binary):
    """Return list of all conditional jumps in key-value set"""
    # List for jumps to return
    jmps = []

    # Analysis on binary to find jumps
    with open(binary, "rb") as fp:
        elf = ELFFile(fp)
        section = elf.get_section_by_name(".text")
        ops = section.data()
        addr = section["sh_addr"]
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # Iterate over parts of .text for conditional jumps
        for instr in md.disasm(ops, addr):
            if "j" in instr.mnemonic and "mp" not in instr.mnemonic:
                jmps.append([instr.address, instr.mnemonic, instr.op_str])

    # Throw it back to the user
    return jmps


def set_break_points(binary):
    """Set breakpoints in GDB. Should only need to be done once."""
    # Get Jumps
    jmps = grab_jmps(binary)

    # Grab base address
    gdb.execute("break main", to_string=True)
    gdb.execute("run", to_string=True)
    procmap = gdb.execute("info proc map", to_string=True).splitlines()
    base_addr = int(procmap[4].split(" ")[6], base=16)

    # Set breakpoints for all jumps
    for jump in jmps:
        gdb.execute(f"break *{hex(jump[0]+base_addr)}", to_string=True)
    #     print(f'Setting break at addr: {hex(jump[0]+base_addr)}')

    # Clean up main breakpoints (should be first one)
    gdb.execute("del bre 1", to_string=True)


# Inspired by https://github.com/mahaloz/Pihulu
def grab_status():
    """Return program status."""
    # List of statuses
    statuses = {
        "It stopped with signal ": "",
        "The program being debugged is not being run.": "NOT RUNNING",
        "It stopped at a breakpoint that has since been deleted.": "TEMPORARY BREAKPOINT",
        "It stopped at breakpoint ": "BREAKPOINT",
        "It stopped after being stepped.": "SINGLE STEP",
    }
    # Get program information
    stat = gdb.execute("info program", to_string=True).splitlines()
    if not stat or len(stat) <= 0:
        return "NOT RUNNING"
    for status in stat:
        for msg in statuses.keys():
            if msg in status:
                if statuses[msg] == "":
                    return status[status.find(statuses[msg]) + len(msg) :]
                else:
                    return statuses[msg]
    return "STOPPED"


def crash_check():
    """Check if the program has crashed."""
    global CURRENT
    # Grab status
    stat = grab_status()

    # Check for seg
    if "SIGSEGV" in stat:
        return True
    return False


def stop():
    """Stop execution of program in GDB. Set for next run."""
    # Setup global variables
    global PREV_ADDR
    global CURRENT_ADDR
    global SHARED_MEM

    # Reset Previous location
    PREV_ADDR = 0


def progress():
    """See if we are still running."""
    # Setup global variables
    global CURRENT_ADDR
    global PREV_ADDR
    global SHARED_MEM
    global CURRENT
    global INPUT_DIR
    global CRASH_DIR

    # Verify no crash
    try:
        assert crash_check() == False
    except AssertionError:
        os.system(f"cp {INPUT_DIR}/{CURRENT} ./{CRASH_DIR}/.")
        stop()
        return

    # Grab PC
    try:
        pc = gdb.execute("info registers pc", to_string=True)
        pc = pc.split(" ")[13].split("\t")[0]
    except:
        stop()
        return
    else:
        CURRENT_ADDR = int(pc, 0)
        SHARED_MEM[(CURRENT_ADDR ^ PREV_ADDR) % 64000] += 1
        PREV_ADDR = CURRENT_ADDR >> 1

    # Continue
    gdb.execute("continue", to_string=True)
    progress()


def run(data_in):
    """Start program with input."""
    # Set global vars
    global SHARED_MEM
    global INPUT_DIR

    # Reset shared memory to zero state
    SHARED_MEM = [0] * (64 * 1024)

    # Execute program
    gdb.execute(f"run < ./{INPUT_DIR}/{data_in}", to_string=True)

    # Store current progress
    progress()


def check_uniq():
    """Check if map is unique to global maps."""
    global GLOBAL_MAPPINGS
    global SHARED_MEM

    # Iterate over all the global mappings
    for mapping in GLOBAL_MAPPINGS:
        if SHARED_MEM == mapping:
            return False
    return True


def main(binary):
    """Run program loop."""
    global GLOBAL_MAPPINGS
    global SHARED_MEM
    global CURRENT
    global INPUT_DIR
    global CRASH_DIR

    # Local vars
    INPUT_DIR = gdb.execute("p $indir", to_string=True).split('"')[1]
    CRASH_DIR = gdb.execute("p $crash", to_string=True).split('"')[1]

    # Define Fuzzer object
    fuz = Fuzzer(input_queue_directory=INPUT_DIR)

    # Set initial break_points
    set_break_points(binary)

    # Check if input dir is empty
    if len(os.listdir(INPUT_DIR)) <= 0:
        # Generate random input via library
        fuz.get_input_file()

    # Instantiate queue. Set the queue to the input folder
    q = queue.deque(os.listdir(INPUT_DIR))
    stats_last = 0

    while len(q) > 0:
        # Grab file name from queue
        CURRENT = f"{q.popleft()}"

        # Obtain file data
        """
        sends file name
        returns list of file names
        """
        mutations: List[str] = fuz.mutate(CURRENT)  # This is where we call the mutations function

        # Iterate through all mutations and throw out bad ones
        for mutation in mutations:
            CURRENT = mutation
            run(CURRENT)
            if check_uniq():
                q.append(mutation)
                GLOBAL_MAPPINGS.append(SHARED_MEM)
            else:
                os.remove(f"{INPUT_DIR}/{mutation}")

        # Print status
        eprint(" " * stats_last + "\r", end="")
        stats = f"Current queue size: {len(q)}\r"
        eprint(stats, end="")
        stats_last = len(stats)

    # Cleanup and exit
    os.system("rm gdbinit")
    eprint(f"\nUnique Paths: {len(GLOBAL_MAPPINGS)}")
    gdb.execute("quit", to_string=True)
    return


# Indirect name pass
binary = gdb.current_progspace().filename
main(binary)

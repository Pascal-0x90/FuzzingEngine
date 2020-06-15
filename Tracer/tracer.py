#!/usr/bin/env python3

# Third-Party Libraries
from elftools.elf.elffile import ELFFile
from capstone import *
import gdb

# Global Variables
CURRENT_ADDR = 0
PREV_ADDR = 0
SHARED_MEM = [0]*(64*1024) # ~1 mb 

def grab_jmps(binary):
    """Return list of all conditional jumps in key-value set"""
    jmps = []
    with open(binary, 'rb') as fp:
        elf = ELFFile(fp)
        section = elf.get_section_by_name('.text')
        ops = section.data()
        addr = section['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for instr in md.disasm(ops, addr):
            if "j" in instr.mnemonic and "mp" not in instr.mnemonic:
                jmps.append([instr.address, instr.mnemonic, instr.op_str])
    return jmps

def set_break_points(binary):
    """Set breakpoints in GDB."""
    # Get Jumps
    jmps = grab_jmps(binary)

    # Grab base address
    gdb.execute('break main')
    gdb.execute('run')
    procmap = gdb.execute('info proc map', to_string=True).splitlines()
    base_addr = int(procmap[4].split(" ")[6],base=16)

    # Set breakpoints for all jumps
    for jump in jmps:
        print(gdb.execute(f'break *{hex(jump[0]+base_addr)}',to_string=True))
        print(f'Setting break at addr: {hex(jump[0]+base_addr)}')

    # Clean up main breakpoints (should be first one)
    gdb.execute("del bre 1")

# Inspired by https://github.com/mahaloz/Pihulu
def grab_status():
    """Return program status."""
    # List of statuses
    statuses = {"It stopped with signal ":"",
                "The program being debugged is not being run.":"NOT RUNNING",
                "It stopped at a breakpoint that has since been deleted.":"TEMPORARY BREAKPOINT",
                "It stopped at breakpoint ": "BREAKPOINT",
                "It stopped after being stepped.":"SINGLE STEP"}
    # Get program information
    stat = gdb.execute("info program", to_string=True).splitlines()
    if not stat or len(stat) <= 0:
        return "NOT RUNNING"
    for status in stat:
        for msg in statuses.keys():
            if msg in status:
                if statuses[msg] == "":
                    return status[status.find(statuses[msg])+len(msg):]
                else:
                    return statuses[msg]

def check_pulse():
    """See if we are still running."""
    global CURRENT_ADDR
    global PREV_ADDR

    # Grab PC
    try:
        pc = gdb.execute("info registers pc", to_string=True)
        pc = pc.split(" ")[13].split("\t")[0]
    except:
        return
    else:
        CURRENT_ADDR = int(pc,0)
        SHARED_MEM[(CURRENT_ADDR ^ PREV_ADDR) % 64000] += `
        PREV_ADDR = CURRENT_ADDR >> 1

def fuzin():
    """Determine if the program has crashed or not."""
    # Grab overall program status
    stat = grab_status()

    # Determine SIGSEV
    if "SIGSEGV" in stat:
        check_pulse()
        print("="*10+"PROGRAM CRASH"+"="*10)
        print(f"Crashed at: {CURRENT_ADDR}")
        print(f"Last Successful: {PREV_ADDR}")
        return

    # Check to see if we are alive
    check_pulse()

set_break_points("./chall.elf")

#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile
from capstone import *
import gdb

def grab_jmps(binary):
    """Return list of all conditional jumps in key-value set"""
    jmps = []
    with open(binary, 'rb') as fp:
        elf = ELFFile(fp)
        for section in elf.iter_sections():
            ops = section.data()
            addr = section['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for instr in md.disasm(ops, addr):
                if "j" in instr.mnemonic and "mp" not in instr.mnemonic:
                    jmps.append([instr.address, instr.mnemonic, instr.op_str])
    return jmps

def trace(binary):
    jmps = grab_jmps(binary)
    gdb.execute('break main')
    gdb.execute('run')
    procmap = gdb.execute('info proc map', to_string=True)
    print(procmap)
    #for jump in jmps:
    #    gdb.execute(f'break *{jump[0]}',to_string=True)
    #    print(f'Setting break at addr: {hex(jump[0])}')

trace("./chall.elf")

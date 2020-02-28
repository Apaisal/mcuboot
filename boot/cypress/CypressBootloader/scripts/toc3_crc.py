"""
Copyright (c) 2019 Cypress Semiconductor Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import click
import os
from elftools.elf.elffile import *
from intelhex import IntelHex

INIT_VALUE_XMODEM = 0xFFFF
POLY_VALUE_CCITT_NORMAL = 0x1021

def crc16_ccitt(data, initial_value=INIT_VALUE_XMODEM, poly=POLY_VALUE_CCITT_NORMAL):
    crc = initial_value
    for it in data:
        crc = (crc ^ it << 8)
        for _ in range(0,8):
            if (crc & 0x8000):
                crc <<= 1
                crc ^= poly
            else:
                crc <<= 1
    return crc & 0xFFFF


@click.command()
@click.argument('infile')
@click.argument('outfile')

def main(infile, outfile):
    result = -1
    if (os.path.isfile(infile)):
        hex_file = infile.replace('.elf', '.hex')
        if (os.path.isfile(hex_file)):
            elf = ELFFile(open(infile, 'rb'))
            ih = IntelHex(hex_file)
            sec = elf.get_section_by_name('.cy_toc_part2')
            if sec:
                sec_start_addr = sec.header['sh_addr']
                sec_size = sec.header['sh_size']
                ih.puts(sec_start_addr + sec_size - 2, struct.pack('<H', crc16_ccitt(ih.tobinarray(start=sec_start_addr, size=sec_size-4))))
                ih.write_hex_file(outfile)
                result = 0
            else:
                print(f"ERROR. In file {infile} section .cy_toc_part2 not found!")
        else:
            print(f"ERROR. Input file {hex_file} not found!")
    else:
        print(f"ERROR. Input file {infile} not found!")
    return result


if __name__ == "__main__":
    main()
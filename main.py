from pwn import *
import struct

types = {
    "char":  ("B", 1),
    "short": ("H", 2),
    "int":   ("I", 4),
    "long":  ("Q", 8),
    "ptr":   ("Q", 8)
}

class Binary:
    def __init__(self, path):
        self.elf = ELF(path)

    def read_C_array(self, offset, count, _type="char"):
        print(f"Reading {count} {_type} values from offset {hex(offset)}")
        
        data = self.elf.read(offset, count * types[_type][1])
        return struct.unpack(f"<{count}{types[_type][0]}", data)

    def read_C_string(self, offset):
        ptr = offset
        while self.elf.read(ptr, 1) != b'\x00':
            ptr += 1
        return self.elf.read(offset, ptr - offset).decode("ASCII")

filename = "./file.elf"
bin = Binary(filename)

start, end = 0x602080, 0x6020C0
count = end - start

data = bin.read_C_array(start, count, "char")
print(data)

start, end = 0x6020C0, 0x6026F0
count = (end - start) // types["ptr"][1]

addrs = bin.read_C_array(start, count, "ptr")
print(addrs)

for i in addrs:
    print(bin.read_C_string(i), end=" ")

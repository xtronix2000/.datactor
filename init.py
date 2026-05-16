from elftools.elf.elffile import ELFFile
import struct
import sys
import json

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

def disasm_at(elf_data, load_offset, vaddr, size=64):
    if not HAS_CAPSTONE:
        return ["capstone not installed"]
    
    file_offset = vaddr - load_offset
    if file_offset < 0:
        return ["offset error"]
    
    code = elf_data[file_offset:file_offset + size]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    result = []
    for insn in md.disasm(code, vaddr):
        result.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    return result

def get_load_offset(elf):
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_offset'] == 0:
            return seg['p_vaddr']
    return 0

def extract_init_sections(path):
    result = {"file": path, "sections": {}, "constructors_disasm": {}}
    
    with open(path, "rb") as f:
        raw = f.read()
        f.seek(0)
        elf = ELFFile(f)
        load_offset = get_load_offset(elf)
        
        interesting = [".init", ".fini", ".init_array", ".fini_array"]
        
        for name in interesting:
            section = elf.get_section_by_name(name)
            if not section:
                continue
            
            data = section.data()
            addr = section["sh_addr"]
            entry = {
                "addr": hex(addr),
                "size": len(data),
                "bytes": data.hex()
            }
            
            if name in (".init_array", ".fini_array"):
                ptrs = []
                for i in range(0, len(data), 8):
                    ptr = struct.unpack_from("<Q", data, i)[0]
                    ptrs.append(hex(ptr))
                entry["function_pointers"] = ptrs
                
                # Дизассемблируем каждый конструктор
                for ptr_hex in ptrs:
                    ptr = int(ptr_hex, 16)
                    disasm = disasm_at(raw, load_offset, ptr, size=128)
                    result["constructors_disasm"][ptr_hex] = disasm
            
            result["sections"][name] = entry
    
    return result

if __name__ == "__main__":
    for path in sys.argv[1:]:
        if not path.endswith(".so") and not path.split(".")[-1].startswith("so"):
            continue
        try:
            data = extract_init_sections(path)
            print(json.dumps(data, indent=2))
        except Exception as e:
            print(f"ERROR {path}: {e}", file=sys.stderr)
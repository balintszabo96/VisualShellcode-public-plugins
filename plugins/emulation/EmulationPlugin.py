import ctypes
from typing import TypeAlias

class Instruction:
    def __init__(self, address, opcodes, operation, text):
        self.address = address
        self.address_num = int(address, 16)
        self.opcodes = opcodes
        self.operation = operation
        self.text = text

Instructions: TypeAlias = list[Instruction]

class Flag:
    def __init__(self, address, name, taken_instructions):
        self.address = address
        self.name = name
        self.taken_instructions = taken_instructions

    def take_instructions(self) -> Instructions:
        taken_instructions = []
        for instruction in self.taken_instructions:
            if self.address == instruction.address_num:
                taken_instructions.append(instruction)
                break
            taken_instructions.append(instruction)
        return taken_instructions
    
    def is_this_it(self, instruction: Instruction) -> bool:
        return self.address == instruction.address_num

class EmulationPlugin:
    def __init__(self):
        self.altitude = 1

    def process(self, handle, input, architecture):
        shellcode = bytes.fromhex(input)
        buff = ctypes.create_string_buffer(shellcode, len(shellcode))
        shemuStatus = ctypes.c_uint32(0)
        shemuStatusPtr = ctypes.pointer(shemuStatus)
        flags = ctypes.c_uint64(0)
        flagsPtr = ctypes.pointer(flags)
        result = ctypes.c_int32(0)    
        bufsize = 100000
        emuRes = ctypes.create_string_buffer(bufsize)
        instrBuffer = ctypes.create_string_buffer(bufsize)
        handle.ExpAnalyzeShellcode.argtypes = [ctypes.c_char_p, ctypes.c_int32, ctypes.c_bool, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint64), ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_uint64]
        handle.ExpAnalyzeShellcode.restype = ctypes.c_int32
        result = handle.ExpAnalyzeShellcode(buff, len(shellcode), architecture == 'x86', shemuStatusPtr, flagsPtr, emuRes, bufsize, instrBuffer, bufsize)
        emulation = emuRes.value.decode()
        passed_instructions = []
        disasm_lines = instrBuffer.value.decode().split('\n')[:-1]
        for line in disasm_lines:
            trimmed = ' '.join(line.split())
            line_split = trimmed.split(' ')
            address = line_split[0]
            opcodes = line_split[1]
            operation = line_split[2]
            text = ' '.join(line_split[3:])
            passed_instructions.append(Instruction(address, opcodes, operation, text))

        flags = []
        address_flags = emulation.split(';')[:-1]
        for address_flag in address_flags:
            address = int(address_flag.split(',')[0])
            flag = address_flag.split(',')[1]
            flags.append(Flag(address, flag, passed_instructions))
        
        return flags
import ctypes

class Instruction:
    def __init__(self, address, opcodes, operation, text):
        self.address = address
        self.address_num = int(address, 16)
        self.opcodes = opcodes
        self.operation = operation
        self.text = text

class DisassemblyPlugin:
    def __init__(self) -> None:
        self.altitude = 100

    def process(self, handle, input, architecture):
        shellcode = bytes.fromhex(input)
        buff = ctypes.create_string_buffer(shellcode, len(shellcode))
        
        #result = ctypes.c_int32(0)
        bufsize = 100000
        disasm = ctypes.create_string_buffer(bufsize)
        handle.ExpDisasmShellcode.argtypes = [ctypes.c_char_p, ctypes.c_int32, ctypes.c_bool, ctypes.c_char_p, ctypes.c_uint64]
        handle.ExpDisasmShellcode.restype = ctypes.c_int32
        handle.ExpDisasmShellcode(buff, len(shellcode), architecture == 'x86', disasm, bufsize)

        disasm_lines = disasm.value.decode().split('\n')[:-1]
        instructions = []
        for line in disasm_lines:
            trimmed = ' '.join(line.split())
            line_split = trimmed.split(' ')
            address = line_split[0]
            opcodes = line_split[1]
            operation = line_split[2]
            text = ' '.join(line_split[3:])
            instructions.append(Instruction(address, opcodes, operation, text))
        return instructions
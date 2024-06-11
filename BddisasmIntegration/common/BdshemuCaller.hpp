#pragma once
#include <stdint.h>
#include <stdlib.h>
#include "bdshemu.h"
#include "bddisasm.h"

enum class Status
{
    Success = 0,
    Unsuccessful,
    MallocFailed,
};

int
AnalyzeShellcode(unsigned char* Shellcode, uint32_t Size, bool Is32Bit, unsigned int* ShemuStatus, uint64_t* Flags, char* Buffer, uint64_t BufSize, char* InstrBuffer, uint64_t InstrBufferSize);

int
DisassembleShellcode(unsigned char* Shellcode, uint32_t Size, bool Is32Bit, char* Buffer, uint64_t BufSize);
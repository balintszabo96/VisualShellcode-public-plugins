#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>
#include "BdshemuCaller.hpp"
#include <vector>
#include <string>
#include <memory>

extern "C" {
#if !defined(BDDISASM_HAS_VSNPRINTF)
    //
    // nd_vsnprintf
    //
    int
        nd_vsnprintf_s(
            char* buffer,
            size_t sizeOfBuffer,
            size_t count,
            const char* format,
            va_list argptr
        )
    {
        return _vsnprintf_s(buffer, sizeOfBuffer, count, format, argptr);
    }
#endif // !defined(BDDISASM_HAS_VSNPRINTF)

#if !defined(BDDISASM_HAS_MEMSET)
    void*
        nd_memset(void* s, int c, size_t n)
    {
        return memset(s, c, n);
    }
#endif // !defined(BDDISASM_HAS_MEMSET)
}

ND_BOOL
MemAccess(
    void* ShemuContext, // Shemu emulation context.
    ND_UINT64 Gla,      // Linear address to be accessed.
    ND_SIZET Size,      // Number of bytes to access.
    ND_UINT8* Buffer,   // Contains the read content (if Store is false), or the value to be stored at Gla.
    ND_BOOL Store       // If false, read content at Gla. Otherwise, write content at Gla.
)
{
    return true;
}

typedef struct _FLAG_DATA
{
    uint64_t Address = 0;
    const char* Flag = nullptr;
}FLAG_DATA, *PFLAG_DATA;

typedef struct _FLAGS
{
    FLAG_DATA Flags[100] = { 0 };
    byte LastUsedIndex = 0;
}FLAGS, *PFLAGS;

typedef struct _LOGCTX {
    PSHEMU_CONTEXT CurrentCtx;
    PSHEMU_CONTEXT PrevCtx;
    FLAGS FlagInfo = { 0 };
    std::shared_ptr<std::vector<std::pair<uint64_t, std::string>>> TraversedInstructions;
}LOGCTX, *PLOGCTX;

typedef struct _FLAG_NAME
{
    uint64_t Flag;
    const char* Name;
}FLAG_NAME, *PFLAG_NAME;

static FLAG_NAME gFlagNames[] =
{
    {SHEMU_FLAG_NOP_SLED         , "NOP_SLED"},
    {SHEMU_FLAG_LOAD_RIP         , "LOAD_RIP"},
    {SHEMU_FLAG_WRITE_SELF       , "WRITE_SELF"},
    {SHEMU_FLAG_TIB_ACCESS       , "TIB_ACCESS"},
    {SHEMU_FLAG_SYSCALL          , "SYSCALL"},
    {SHEMU_FLAG_STACK_STR        , "STACK_STR"},
    {SHEMU_FLAG_TIB_ACCESS_WOW32 , "TIB_ACCESS_WOW32"},
    {SHEMU_FLAG_HEAVENS_GATE     , "HEAVENS_GATE"},
    {SHEMU_FLAG_STACK_PIVOT      , "STACK_PIVOT"},
    {SHEMU_FLAG_SUD_ACCESS       , "SUD_ACCESS"},
    {SHEMU_FLAG_KPCR_ACCESS      , "KPCR_ACCESS"},
    {SHEMU_FLAG_SWAPGS           , "SWAPGS"},
    {SHEMU_FLAG_SYSCALL_MSR_READ , "SYSCALL_MSR_READ"},
    {SHEMU_FLAG_SYSCALL_MSR_WRITE, "SYSCALL_MSR_WRITE"},
    {SHEMU_FLAG_SIDT             , "SIDT"}
};
static uint16_t gFlagNamesSize = _ARRAYSIZE(gFlagNames);

const char* gSpaces[16] =
{
    "",
    "  ",
    "    ",
    "      ",
    "        ",
    "          ",
    "            ",
    "              ",
    "                ",
    "                  ",
    "                    ",
    "                      ",
    "                        ",
    "                          ",
    "                            ",
    "                              ",
};

void
CatToBuffer(char* Dst, uint64_t DstSize, char* Src)
{
    uint64_t dstUsed = strlen(Dst);
    uint64_t dstRemaining = DstSize - dstUsed;
    if (dstRemaining > strlen(Src))
    {
        strcat_s(Dst, DstSize, Src);
    }
}

void
print_instruction(
    __in SIZE_T Rip,
    __in PINSTRUX Instrux,
    __in char* Buffer,
    __in uint64_t BufSize
)
{
    char instruxText[ND_MIN_BUF_SIZE];
    DWORD k = 0, idx = 0, i = 0;
    CHAR tempBuf[1000] = { 0 };

    sprintf_s(tempBuf, 1000, "%p ", (void*)(Rip));
    CatToBuffer(Buffer, BufSize, tempBuf);
    RtlZeroMemory(tempBuf, 1000);

    for (; k < Instrux->Length; k++)
    {
        sprintf_s(tempBuf, 1000, "%02x", Instrux->InstructionBytes[k]);
        CatToBuffer(Buffer, BufSize, tempBuf);
        RtlZeroMemory(tempBuf, 1000);
    }

    //sprintf_s(tempBuf, 1000, "%s", gSpaces[16 - (Instrux->Length & 0xF)]);
    strcat_s(Buffer, BufSize, " ");
    //RtlZeroMemory(tempBuf, 1000);

    NdToText(Instrux, Rip, ND_MIN_BUF_SIZE, instruxText);

    sprintf_s(tempBuf, 1000, "%s\n", instruxText);
    CatToBuffer(Buffer, BufSize, tempBuf);
    RtlZeroMemory(tempBuf, 1000);
}

void
InstructionCallback(
    char* Data,
    void* Context
)
{
    PLOGCTX ctx = reinterpret_cast<PLOGCTX>(Context);
    uint64_t instrOffset = 0;
    if (ctx->CurrentCtx->InstructionsCount > 1)
    {
        instrOffset = ctx->PrevCtx->Arch.X86.Registers.RegRip - ctx->PrevCtx->ShellcodeBase;
    }
    else
    {
        instrOffset = ctx->CurrentCtx->Arch.X86.Registers.RegRip - ctx->CurrentCtx->ShellcodeBase;
    }

    if (Data && strstr(Data, "IP:"))
    {
        bool found = false;
        for (auto const& addrInstr : *ctx->TraversedInstructions.get())
        {
            if (addrInstr.first == instrOffset)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            CHAR tempBuf[100] = { 0 };
            print_instruction(instrOffset, &ctx->CurrentCtx->Arch.X86.Instruction, tempBuf, 100);
            auto pr = std::make_pair(instrOffset, std::string(tempBuf));
            ctx->TraversedInstructions->emplace_back(std::move(pr));
        }
    }
    if (ctx->CurrentCtx->Flags != ctx->PrevCtx->Flags)
    {
        uint64_t negatedUntilNow = ~ctx->PrevCtx->Flags;
        uint64_t newFlags = ctx->CurrentCtx->Flags & negatedUntilNow;

        for (uint16_t i = 0; i < gFlagNamesSize; i++)
        {
            if ((newFlags & gFlagNames[i].Flag) == gFlagNames[i].Flag)
            {
                ctx->FlagInfo.Flags[ctx->FlagInfo.LastUsedIndex].Address = instrOffset;
                ctx->FlagInfo.Flags[ctx->FlagInfo.LastUsedIndex].Flag = gFlagNames[i].Name;
                ctx->FlagInfo.LastUsedIndex++;
            }
        }
    }
    RtlCopyMemory(ctx->PrevCtx, ctx->CurrentCtx, sizeof(SHEMU_CONTEXT));
}

int
AnalyzeShellcode(unsigned char* Shellcode, uint32_t Size, bool Is32Bit, unsigned int* ShemuStatus, uint64_t* Flags, char* Buffer, uint64_t BufSize, char* InstrBuffer, uint64_t InstrBufferSize)
{
    Status status = Status::Unsuccessful;
    uint64_t shellcodeAddress = reinterpret_cast<uint64_t>(Shellcode);
    uint8_t* stack = nullptr;
    uint8_t* internalBuffer = nullptr;
    size_t internalBufferSize = 0;
    PLOGCTX logCtx = nullptr;
    SHEMU_CONTEXT* prevCtx = nullptr;
    CHAR tempBuf[100] = { 0 };

    SHEMU_CONTEXT* ctx = reinterpret_cast<SHEMU_CONTEXT*>(malloc(sizeof(SHEMU_CONTEXT)));
    if (!ctx)
    {
        status = Status::MallocFailed;
        goto cleanup;
    }
    memset(ctx, 0, sizeof(SHEMU_CONTEXT));

    prevCtx = reinterpret_cast<SHEMU_CONTEXT*>(malloc(sizeof(SHEMU_CONTEXT)));
    if (!prevCtx)
    {
        status = Status::MallocFailed;
        goto cleanup;
    }
    memset(prevCtx, 0, sizeof(SHEMU_CONTEXT));

    logCtx = reinterpret_cast<PLOGCTX>(malloc(sizeof(LOGCTX)));
    if (!logCtx)
    {
        status = Status::MallocFailed;
        goto cleanup;
    }
    memset(logCtx, 0, sizeof(LOGCTX));

    logCtx->CurrentCtx = ctx;
    logCtx->PrevCtx = prevCtx;
    logCtx->TraversedInstructions = std::make_shared<std::vector<std::pair<uint64_t, std::string>>>();
    //{
    //    CHAR temp[100] = { 0 };
    //    strcpy_s(temp, 100, "balint");
    //    logCtx->TraversedInstructions.emplace_back(1, temp);
    //}
    //logCtx->TraversedInstructions.emplace_back(2, "ervin");

    // set shellcode address
    ctx->Shellcode = reinterpret_cast<ND_UINT8*>(shellcodeAddress);

    // base must be on 32 bits if the shellcode is of 32 bits
    ctx->ShellcodeBase = (Is32Bit) ? (0xffffffff & shellcodeAddress) : shellcodeAddress;
    ctx->Arch.X86.Registers.RegRip = (Is32Bit) ? (0xffffffff & shellcodeAddress) : shellcodeAddress;
    ctx->ShellcodeSize = Size;
    ctx->Arch.X86.Ring = 3;
    ctx->Arch.X86.Mode = (Is32Bit) ? ND_CODE_32 : ND_CODE_64;
    ctx->StackSize = 0x2000;
    stack = reinterpret_cast<uint8_t*>(malloc(ctx->StackSize));
    if (!stack)
    {
        status = Status::MallocFailed;
        goto cleanup;
    }

    ctx->Stack = stack;
    // TODO: Make this safe
    // stack starts at high addresses, so we add Stack + StackSize
    // by decrementing it, we simulate allocating space for variables
    ctx->Arch.X86.Registers.RegRsp = reinterpret_cast<uint64_t>(ctx->Stack) + ctx->StackSize - 0x100;
    ctx->StackBase = (Is32Bit) ? (0xffffffff & reinterpret_cast<uint64_t>(stack)) : reinterpret_cast<uint64_t>(stack);

    // TODO: Make this safe
    internalBufferSize = Size + ctx->StackSize;
    internalBuffer = reinterpret_cast<uint8_t*>(malloc(internalBufferSize));
    if (!internalBuffer)
    {
        status = Status::MallocFailed;
    }

    ctx->Intbuf = internalBuffer;
    ctx->IntbufSize = internalBufferSize;
    memset(ctx->Intbuf, 0, internalBufferSize);

    ctx->MaxInstructionsCount = 10000;
    ctx->NopThreshold = 75;
    ctx->StrThreshold = 8;
    ctx->MemThreshold = 100;

    ctx->Arch.X86.Registers.RegCr0 = 0x80050031;
    ctx->Arch.X86.Registers.RegCr2 = 0;
    ctx->Arch.X86.Registers.RegCr3 = 0x1aa000;
    ctx->Arch.X86.Registers.RegCr4 = 0x170678;
    ctx->Arch.X86.Registers.RegFlags = 0x202;

    ctx->TibBase = Is32Bit ? 0xCABC0000 : 0x00008ABC00000000;

    if (ctx->Arch.X86.Mode == ND_CODE_64)
    {
        ctx->Arch.X86.Segments.Cs.Selector = (ctx->Arch.X86.Ring == 3) ? 0x33 : 0x10;
        ctx->Arch.X86.Segments.Ds.Selector = (ctx->Arch.X86.Ring == 3) ? 0x2b : 0x18;
        ctx->Arch.X86.Segments.Es.Selector = (ctx->Arch.X86.Ring == 3) ? 0x2b : 0x18;
        ctx->Arch.X86.Segments.Ss.Selector = (ctx->Arch.X86.Ring == 3) ? 0x2b : 0x18;
        ctx->Arch.X86.Segments.Fs.Selector = (ctx->Arch.X86.Ring == 3) ? 0x2b : 0x00;
        ctx->Arch.X86.Segments.Gs.Selector = (ctx->Arch.X86.Ring == 3) ? 0x53 : 0x00;

        ctx->Arch.X86.Segments.Fs.Base = 0;
        ctx->Arch.X86.Segments.Gs.Base = 0;
        ctx->TibBase = ctx->Arch.X86.Segments.Gs.Base;
    }
    else
    {
        ctx->Arch.X86.Segments.Cs.Selector = (ctx->Arch.X86.Ring == 3) ? 0x1b : 0x08;
        ctx->Arch.X86.Segments.Ds.Selector = (ctx->Arch.X86.Ring == 3) ? 0x23 : 0x10;
        ctx->Arch.X86.Segments.Es.Selector = (ctx->Arch.X86.Ring == 3) ? 0x23 : 0x10;
        ctx->Arch.X86.Segments.Ss.Selector = (ctx->Arch.X86.Ring == 3) ? 0x23 : 0x10;
        ctx->Arch.X86.Segments.Fs.Selector = (ctx->Arch.X86.Ring == 3) ? 0x3b : 0x30;
        ctx->Arch.X86.Segments.Gs.Selector = (ctx->Arch.X86.Ring == 3) ? 0x23 : 0x00;

        ctx->Arch.X86.Segments.Fs.Base = 0;
        ctx->Arch.X86.Segments.Gs.Base = 0;
        ctx->TibBase = ctx->Arch.X86.Segments.Fs.Base;
    }

    ctx->AccessMemory = MemAccess;
    ctx->Options |= SHEMU_OPT_TRACE_EMULATION;
    ctx->Log = InstructionCallback;
    ctx->AuxData = logCtx;
    ctx->ArchType = SHEMU_ARCH_TYPE_X86;
    *ShemuStatus = ShemuEmulate(ctx);
    // call one last time so that we get the flag even if it's at the last instruction
    InstructionCallback(NULL, logCtx);
    *Flags = ctx->Flags;

    for (uint16_t i = 0; i < logCtx->FlagInfo.LastUsedIndex; i++)
    {
        sprintf_s(tempBuf, 100, "%d,%s;", logCtx->FlagInfo.Flags[i].Address, logCtx->FlagInfo.Flags[i].Flag);
        uint64_t tempBufLen = strlen(tempBuf);
        uint64_t bufUsed = strlen(Buffer);
        if (tempBufLen < BufSize - bufUsed)
        {
            strcat_s(Buffer, BufSize, tempBuf);
        }
        else
        {
            break;
        }
        RtlZeroMemory(tempBuf, tempBufLen);
    }

    for (auto const& instrAddr : *logCtx->TraversedInstructions.get())
    {
        sprintf_s(tempBuf, 100, "%s", instrAddr.second.c_str());
        uint64_t tempBufLen = strlen(tempBuf);
        uint64_t bufUsed = strlen(InstrBuffer);
        if (tempBufLen < InstrBufferSize - bufUsed)
        {
            strcat_s(InstrBuffer, InstrBufferSize, tempBuf);
        }
        else
        {
            break;
        }
        RtlZeroMemory(tempBuf, tempBufLen);
    }

    status = Status::Success;
cleanup:
    if (internalBuffer)
    {
        free(internalBuffer);
    }
    if (stack)
    {
        free(stack);
    }
    if (ctx)
    {
        free(ctx);
    }
    if (prevCtx)
    {
        free(prevCtx);
    }
    if (logCtx)
    {
        logCtx->TraversedInstructions->clear();
        free(logCtx);
    }
    return static_cast<int>(status);
}

int
DisassembleShellcode(unsigned char* Shellcode, uint32_t Size, bool Is32Bit, char* Buffer, uint64_t BufSize)
{
    Shellcode;
    Size;
    Is32Bit;
    Buffer;
    BufSize;

    // code copied from disasmtool
    INSTRUX instrux;
    ND_CONTEXT ctx = { 0 };
    unsigned long long icount = 0, istart, iend, itotal = 0, tilen = 0, ticount = 0;
    SIZE_T rip, fsize = Size;
    PBYTE buffer = Shellcode;
    CHAR tempBuf[1000] = { 0 };

    NdInitContext(&ctx);

    ctx.DefCode = Is32Bit ? ND_CODE_32 : ND_CODE_64;
    ctx.DefData = Is32Bit ? ND_CODE_32 : ND_CODE_64;
    ctx.DefStack = Is32Bit ? ND_CODE_32 : ND_CODE_64;
    ctx.VendMode = ND_VEND_ANY; // DON'T CARE
    ctx.FeatMode = ND_FEAT_ALL;

    // Disassemble
    rip = 0;
    while (rip < Size)
    {
        NDSTATUS status;

        icount++;

#if defined(ND_ARCH_X86) || defined(ND_ARCH_X64)
        istart = __rdtsc();
#else
        istart = 0;
#endif

        status = NdDecodeWithContext(&instrux, buffer + rip, fsize - rip, &ctx);

#if defined(ND_ARCH_X86) || defined(ND_ARCH_X64)
        iend = __rdtsc();
#else
        iend = 1;
#endif
        if (BufSize - strlen(Buffer) < 150)
        {
            return 99;
        }
        itotal += iend - istart;
        if (!ND_SUCCESS(status))
        {
            sprintf_s(tempBuf, 1000, "%p ", (void*)(rip));
            CatToBuffer(Buffer, BufSize, tempBuf);
            RtlZeroMemory(tempBuf, 1000);

            sprintf_s(tempBuf, 1000, "%02x", buffer[rip]);
            CatToBuffer(Buffer, BufSize, tempBuf);
            RtlZeroMemory(tempBuf, 1000);

            sprintf_s(tempBuf, 1000, "%s", gSpaces[16 - 1]);
            CatToBuffer(Buffer, BufSize, tempBuf);
            RtlZeroMemory(tempBuf, 1000);

            sprintf_s(tempBuf, 1000, "db 0x%02x (0x%08x)\n", buffer[rip], status);
            CatToBuffer(Buffer, BufSize, tempBuf); 
            RtlZeroMemory(tempBuf, 1000);

            rip++;
        }
        else
        {
            tilen += instrux.Length;
            ticount++;

            print_instruction(rip, &instrux, Buffer, BufSize);

            rip += instrux.Length;
        }
    }
    return 99;
}
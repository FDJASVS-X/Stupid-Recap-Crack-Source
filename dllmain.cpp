#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <intrin.h>
#include <memoryapi.h>

uintptr_t _security_cookie = 0x2B992DDFA232LL;
HANDLE hHeap = nullptr;
DWORD synchronizationVariable = 0;
__int64 moduleHandle;
__int64 securityCheckResult;
void* lpMem = nullptr;
unsigned int memoryCount = 0;
unsigned int memorySize = 0;
unsigned int someStateVariable = 0;

void ThreadInitFunction(LPVOID lpThreadParameter);
unsigned __int64* GetSomeContext();
void ReportFailure(uintptr_t StackCookie);
__int64 MemoryCheckFunction(__int64 a1);
int MemoryCleanupFunction(unsigned __int64* a1);
_BOOL8 MemoryValidationFunction(const void* a1);
__int64 ProcessFunction(__int64 a1, int a2, __int64 a3);
__int64 ThreadCreationFunction(__int64 a1, int a2);
__int64 RandomFunctionForE(__int64 a1);
__int64 RandomFunctionFor344();
void RandomFunctionFor46C(__int64 a1);
void RandomFunctionFor314(__int64 a1);
void RandomFunctionFor7F4(__int64 a1);
unsigned __int8 RandomFunctionFor610(unsigned __int8 a1);
unsigned __int8 RandomFunctionFor634(unsigned __int8 a1, __int64 a2);
void RandomFunctionFor670(int a1);
void capture_previous_context(void* context);
void _raise_securityfailure(struct _EXCEPTION_POINTERS* exceptionInfo);
_BOOL8 __fastcall MemoryValidationFunction(const void* a1)
{
    struct _MEMORY_BASIC_INFORMATION Buffer;

    VirtualQuery(a1, &Buffer, 0x30uLL);
    return Buffer.State == 4096 && (Buffer.Protect & 0xF0) != 0;
}

BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        RandomFunctionFor258();
    }
    return RandomFunctionForEF8(hinstDLL, fdwReason, lpReserved);
}

__int64 __fastcall RandomFunctionForEF8(__int64 a1, unsigned int a2, __int64 a3)
{
    unsigned int v7;
    unsigned int v8;
    __int64 v9;

    if (!a2 && someStateVariable <= 0)
        return 0LL;
    if (a2 - 1 > 1 || (v7 = ProcessFunction(a1, a2, a3)) != 0)
    {
        v8 = ThreadCreationFunction(a1, a2, a3);
        v7 = v8;
        if (a2 == 1 && !v8)
        {
            ThreadCreationFunction(a1, 0LL, a3);
            LOBYTE(v9) = a3 != 0;
            RandomFunctionForE(v9);
        }
        if (!a2 || a2 == 3)
            return (unsigned int)ProcessFunction(a1, a2, a3) != 0;
    }
    return v7;
}

__int64 RandomFunctionFor258() {
    uintptr_t v0 = _security_cookie;
    _FILETIME v2;
    _FILETIME SystemTimeAsFileTime;
    LARGE_INTEGER PerformanceCount;

    if (_security_cookie == 0x2B992DDFA232LL) {
        GetSystemTimeAsFileTime(&SystemTimeAsFileTime);
        v2 = SystemTimeAsFileTime;
        v2.dwLowDateTime ^= GetCurrentThreadId();
        v2.dwHighDateTime ^= GetCurrentProcessId();
        QueryPerformanceCounter(&PerformanceCount);
        v0 = (reinterpret_cast<uintptr_t>(&v2) ^ *reinterpret_cast<uintptr_t*>(&v2) ^ PerformanceCount.QuadPart ^ (PerformanceCount.LowPart << 32)) & 0xFFFFFFFFFFFFLL;
        if (v0 == 0x2B992DDFA232LL) {
            v0 = 0x2B992DDFA233LL;
        }
        _security_cookie = v0;
    }
    securityCheckResult = ~v0;
    return ~v0;
}

__int64 __fastcall StartAddress(LPVOID lpThreadParameter) {
    FILE* v1;
    FILE* Stream;

    ThreadInitFunction(lpThreadParameter);
    AllocConsole();
    v1 = _acrt_iob_func(1u);
    freopen_s(&Stream, "CONOUT$", "w", v1);
    RandomFunctionFor040("Enjoy the crack by Code Red UwU");
    RandomFunctionFor860(memoryCount + 4807120, RandomFunctionFor0A0, &memorySize);
    RandomFunctionForAF0(memoryCount + 4807120);
    RandomFunctionFor860(memoryCount + 4803440, RandomFunctionFor0E0, &unk_1800068D0);
    RandomFunctionForAF0(memoryCount + 4803440);
    RandomFunctionFor860(memoryCount + 4816208, RandomFunctionFor110, &memorySize);
    RandomFunctionForAF0(memoryCount + 4816208);
    RandomFunctionFor860(memoryCount + 4813120, RandomFunctionFor160, &memorySize);
    RandomFunctionForAF0(memoryCount + 4813120);
    return 0LL;
}

__int64 __fastcall RandomFunctionForAF0(__int64 a1)
{
    return RandomFunctionFor480(a1, 1LL);
}

__int64 __fastcall RandomFunctionFor480(__int64 a1, unsigned int a2)
{
    unsigned __int64 i;
    unsigned int v5;
    unsigned int v6;
    _QWORD* v7;
    _BYTE v9[24];

    for (i = 0LL; _InterlockedCompareExchange(&synchronizationVariable, 1, 0); ++i)
        Sleep(i >= 0x20);
    if (hHeap)
    {
        if (a1)
        {
            v6 = 0;
            if (!memoryCount)
                goto LABEL_10;
            v7 = lpMem;
            while (a1 != *v7)
            {
                ++v6;
                v7 += 7;
                if (v6 >= memoryCount)
                    goto LABEL_10;
            }
            if (v6 == -1)
            {
            LABEL_10:
                v5 = 4;
            }
            else if (((*((unsigned __int8*)lpMem + 56 * v6 + 32) >> 1) & 1) == a2)
            {
                v5 = 6 - (a2 != 0);
            }
            else
            {
                RandomFunctionFor6B0(v9, v6, 1LL);
                v5 = RandomFunctionFor5A0(v6, a2);
                RandomFunctionForD50(v9);
            }
        }
        else
        {
            v5 = RandomFunctionFor330(a2);
        }
    }
    else
    {
        v5 = 2;
    }
    _InterlockedExchange(&synchronizationVariable, 0);
    return v5;
}

void __fastcall RandomFunctionForD50(__int64 a1)
{
    __int64 i;
    HANDLE v3;
    void* v4;

    if (*(_QWORD*)a1)
    {
        for (i = 0LL; (unsigned int)i < *(_DWORD*)(a1 + 12); i = (unsigned int)(i + 1))
        {
            v3 = OpenThread(0x5Au, 0, *(_DWORD*)(*(_QWORD*)a1 + 4 * i));
            v4 = v3;
            if (v3)
            {
                ResumeThread(v3);
                CloseHandle(v4);
            }
        }
        HeapFree(hHeap, 0, *(LPVOID*)a1);
    }
}

__int64 __fastcall RandomFunctionFor330(unsigned int a1)
{
    unsigned int v1;
    unsigned int v3;
    unsigned __int8* i;
    unsigned int j;
    DWORD* v7;
    __int64 v8;
    HANDLE v9;
    void* v10;
    LPVOID lpMem;
    unsigned int v12;

    v1 = 0;
    v3 = 0;
    if (memoryCount)
    {
        for (i = (unsigned __int8*)::lpMem + 32; ((*i >> 1) & 1) == a1; i += 56)
        {
            if (++v3 >= memoryCount)
                return 0LL;
        }
        if (v3 != -1)
        {
            RandomFunctionFor6B0(&lpMem, 0xFFFFFFFFLL, a1 != 0);
            for (j = memoryCount; v3 < j; ++v3)
            {
                if (((*((unsigned __int8*)::lpMem + 56 * v3 + 32) >> 1) & 1) != a1)
                {
                    v1 = RandomFunctionFor5A0(v3, a1);
                    if (v1)
                        break;
                    j = memoryCount;
                }
            }
            if (lpMem)
            {
                if (v12)
                {
                    v7 = (DWORD*)lpMem;
                    v8 = v12;
                    do
                    {
                        v9 = OpenThread(0x5Au, 0, *v7);
                        v10 = v9;
                        if (v9)
                        {
                            ResumeThread(v9);
                            CloseHandle(v10);
                        }
                        ++v7;
                        --v8;
                    } while (v8);
                }
                HeapFree(hHeap, 0, lpMem);
            }
        }
    }
    return v1;
}

__int64 __fastcall RandomFunctionFor5A0(unsigned int a1, int a2)
{
    char* v3;
    unsigned __int8 v4;
    _BYTE* v5;
    SIZE_T v6;
    bool v8;
    HANDLE CurrentProcess;
    char v10;
    DWORD flOldProtect;

    v3 = (char*)lpMem + 56 * a1;
    v4 = v3[32] & 1;
    v5 = (_BYTE*)(*(_QWORD*)v3 - 5LL);
    if (!v4)
        v5 = *(_BYTE**)v3;
    v6 = 2LL * v4 + 5;
    if (!VirtualProtect(v5, v6, 0x40u, &flOldProtect))
        return 10LL;
    if (a2)
    {
        *v5 = -23;
        *(_DWORD*)(v5 + 1) = *((_DWORD*)v3 + 2) - (_DWORD)v5 - 5;
        if ((v3[32] & 1) != 0)
            **(_WORD**)v3 = -1557;
    }
    else
    {
        v8 = (v3[32] & 1) == 0;
        *(_DWORD*)v5 = *((_DWORD*)v3 + 6);
        if (v8)
        {
            v5[4] = v3[28];
        }
        else
        {
            *((_WORD*)v5 + 2) = *((_WORD*)v3 + 14);
            v5[6] = v3[30];
        }
    }
    VirtualProtect(v5, v6, flOldProtect, &flOldProtect);
    CurrentProcess = GetCurrentProcess();
    FlushInstructionCache(CurrentProcess, v5, v6);
    v10 = v3[32] ^ (v3[32] ^ (2 * a2)) & 2;
    v3[32] = v10 ^ (v10 ^ (4 * a2)) & 4;
    return 0LL;
}

int __fastcall RandomFunctionFor6B0(__int64 a1)
{
    unsigned int v1;
    HANDLE Toolhelp32Snapshot;
    void* v4;
    _DWORD* v5;
    _DWORD* v6;
    unsigned int v7;
    int v8;
    void* v9;
    THREADENTRY32 te;

    v1 = 0;
    *(_QWORD*)a1 = 0LL;
    *(_QWORD*)(a1 + 8) = 0LL;
    Toolhelp32Snapshot = CreateToolhelp32Snapshot(4u, 0);
    v4 = Toolhelp32Snapshot;
    if (Toolhelp32Snapshot != (HANDLE)-1LL)
    {
        te.dwSize = 28;
        if (Thread32First(Toolhelp32Snapshot, &te))
        {
            do
            {
                if (te.dwSize >= 0x10
                    && te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId())
                {
                    v5 = *(_DWORD**)a1;
                    if (*(_QWORD*)a1)
                    {
                        v7 = *(_DWORD*)(a1 + 8);
                        if (*(_DWORD*)(a1 + 12) >= v7)
                        {
                            v5 = HeapReAlloc(hHeap, 0, *(LPVOID*)a1, 8LL * v7);
                            if (!v5)
                                break;
                            v8 = *(_DWORD*)(a1 + 8);
                            *(_QWORD*)a1 = v5;
                            *(_DWORD*)(a1 + 8) = 2 * v8;
                        }
                    }
                    else
                    {
                        *(_DWORD*)(a1 + 8) = 128;
                        v6 = HeapAlloc(hHeap, 0, 0x200uLL);
                        *(_QWORD*)a1 = v6;
                        v5 = v6;
                        if (!v6)
                            break;
                    }
                    v5[(*(_DWORD*)(a1 + 12))++] = te.th32ThreadID;
                }
                te.dwSize = 28;
            } while (Thread32Next(v4, &te));
        }
        LODWORD(Toolhelp32Snapshot) = CloseHandle(v4);
    }
    if (*(_QWORD*)a1 && *(_DWORD*)(a1 + 12))
    {
        do
        {
            Toolhelp32Snapshot = OpenThread(0x5Au, 0, *(_DWORD*)(*(_QWORD*)a1 + 4LL * v1));
            v9 = Toolhelp32Snapshot;
            if (Toolhelp32Snapshot)
            {
                SuspendThread(Toolhelp32Snapshot);
                RandomFunctionForBA0(v9);
                LODWORD(Toolhelp32Snapshot) = CloseHandle(v9);
            }
            ++v1;
        } while (v1 < *(_DWORD*)(a1 + 12));
    }
    return (int)Toolhelp32Snapshot;
}

int __fastcall RandomFunctionForBA0(HANDLE hThread, unsigned int a2, int a3)
{
    __int64 v6;
    unsigned int v7;
    unsigned int v8;
    DWORD64 Rip;
    __int64 v10;
    __int64 v11;
    char* v12;
    int v13;
    __int64 v14;
    DWORD64 v15;
    _CONTEXT Context;

    Context.ContextFlags = 1048577;
    LODWORD(v6) = GetThreadContext(hThread, &Context);
    if ((_DWORD)v6)
    {
        v7 = memoryCount;
        if (a2 != -1)
            v7 = a2 + 1;
        v8 = 0;
        if (a2 != -1)
            v8 = a2;
        if (v8 < v7)
        {
            Rip = Context.Rip;
            v10 = 56LL * v8;
            v11 = v7 - v8;
            while (1)
            {
                v12 = (char*)lpMem + v10;
                if (a3)
                {
                    if (a3 == 1)
                        v13 = 1;
                    else
                        v13 = ((unsigned __int8)v12[32] >> 2) & 1;
                }
                else
                {
                    v13 = 0;
                }
                LODWORD(v6) = ((unsigned __int8)v12[32] >> 1) & 1;
                if ((_DWORD)v6 == v13)
                    goto LABEL_21;
                if (v13)
                    break;
                if ((v12[32] & 1) == 0 || (v15 = *(_QWORD*)v12, v6 = *(_QWORD*)v12 - 5LL, Rip != v6))
                {
                    v6 = 0LL;
                    if ((*((_DWORD*)v12 + 9) & 0xF) != 0)
                    {
                        while (Rip != *((_QWORD*)v12 + 2) + (unsigned __int8)v12[v6 + 48])
                        {
                            v6 = (unsigned int)(v6 + 1);
                            if ((unsigned int)v6 >= (*((_DWORD*)v12 + 9) & 0xFu))
                                goto LABEL_29;
                        }
                        v15 = *(_QWORD*)v12 + (unsigned __int8)v12[v6 + 40];
                        goto LABEL_19;
                    }
                LABEL_29:
                    if (Rip != *((_QWORD*)v12 + 1))
                        goto LABEL_18;
                    v15 = *(_QWORD*)v12;
                }
            LABEL_19:
                if (v15)
                {
                    Context.Rip = v15;
                    LODWORD(v6) = SetThreadContext(hThread, &Context);
                    Rip = Context.Rip;
                }
            LABEL_21:
                v10 += 56LL;
                if (!--v11)
                    return v6;
            }
            v14 = 0LL;
            if ((*((_DWORD*)v12 + 9) & 0xF) != 0)
            {
                while (1)
                {
                    v6 = *(_QWORD*)v12 + (unsigned __int8)v12[v14 + 40];
                    if (Rip == v6)
                        break;
                    v14 = (unsigned int)(v14 + 1);
                    if ((unsigned int)v14 >= (*((_DWORD*)v12 + 9) & 0xFu))
                        goto LABEL_18;
                }
                v15 = *((_QWORD*)v12 + 2) + (unsigned __int8)v12[v14 + 48];
                goto LABEL_19;
            }
        LABEL_18:
            v15 = 0LL;
            goto LABEL_19;
        }
    }
    return v6;
}

__int64 __fastcall RandomFunctionFor860(__int64 a1, __int64 a2, __int64* a3)
{
    unsigned int v4;
    unsigned __int64 i;
    unsigned int v8;
    _QWORD* v9;
    __int64 v10;
    __int64 v11;
    char* v12;
    unsigned int v13;
    char* v14;
    char v15;
    __int64 v16;
    _QWORD v18[2];
    __int64 v19;
    __int64 v20;
    int v21;
    int v22;
    __int64 v23;
    __int64 v24;

    v4 = 0;
    for (i = 0LL; _InterlockedCompareExchange(&synchronizationVariable, 1, 0); ++i)
        Sleep(i >= 0x20);
    if (!hHeap)
    {
        v4 = 2;
        goto LABEL_33;
    }
    if (!(unsigned int)MemoryValidationFunction(a1) || !(unsigned int)MemoryValidationFunction(a2))
    {
        v4 = 7;
        goto LABEL_33;
    }
    v8 = 0;
    if (memoryCount)
    {
        v9 = lpMem;
        while (a1 != *v9)
        {
            ++v8;
            v9 += 7;
            if (v8 >= memoryCount)
                goto LABEL_10;
        }
        if (v8 != -1)
        {
            v4 = 3;
            goto LABEL_33;
        }
    }
LABEL_10:
    v10 = MemoryCheckFunction(a1);
    v11 = v10;
    if (!v10)
    {
        v4 = 9;
        goto LABEL_33;
    }
    v18[0] = a1;
    v18[1] = a2;
    v19 = v10;
    if (!(unsigned int)ProcessFunction(v18))
    {
        v4 = 8;
        MemoryCleanupFunction(v11);
        goto LABEL_33;
    }
    v12 = (char*)lpMem;
    if (lpMem)
    {
        v13 = memoryCount;
        if (memoryCount < (unsigned int)dword_180006908)
            goto LABEL_23;
        v12 = (char*)HeapReAlloc(hHeap, 0, lpMem, 56LL * (unsigned int)(2 * dword_180006908));
        if (!v12)
            goto LABEL_14;
        lpMem = v12;
        dword_180006908 *= 2;
    }
    else
    {
        dword_180006908 = 32;
        lpMem = HeapAlloc(hHeap, 0, 0x700uLL);
        v12 = (char*)lpMem;
        if (!lpMem)
            goto LABEL_14;
    }
    v13 = memoryCount;
LABEL_23:
    memoryCount = v13 + 1;
    v14 = &v12[56 * v13];
    if (v14)
    {
        v15 = v14[32];
        *(_QWORD*)v14 = v18[0];
        *((_QWORD*)v14 + 1) = v20;
        *((_QWORD*)v14 + 2) = v19;
        v16 = v19;
        v14[32] = v21 & 1 | v15 & 0xF8;
        *((_DWORD*)v14 + 9) = v22 & 0xF | *((_DWORD*)v14 + 9) & 0xFFFFFFF0;
        *((_QWORD*)v14 + 5) = v23;
        *((_QWORD*)v14 + 6) = v24;
        if (v21)
        {
            *((_DWORD*)v14 + 6) = *(_DWORD*)(a1 - 5);
            *((_WORD*)v14 + 14) = *(_WORD*)(a1 - 1);
            v14[30] = *(_BYTE*)(a1 + 1);
        }
        else
        {
            *((_DWORD*)v14 + 6) = *(_DWORD*)a1;
            v14[28] = *(_BYTE*)(a1 + 4);
        }
        if (a3)
            *a3 = v16;
        goto LABEL_15;
    }
LABEL_14:
    v4 = 9;
LABEL_15:
    if (v4)
        MemoryCleanupFunction(v11);
LABEL_33:
    _InterlockedExchange(&synchronizationVariable, 0);
    return v4;
}

int main() {

    DllEntryPoint(GetModuleHandle(NULL), DLL_PROCESS_ATTACH, NULL);
    return 0;
}

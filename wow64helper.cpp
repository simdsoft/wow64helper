#include <Windows.h>
#include <Shlwapi.h>
#include <ShellAPI.h>
#include <stdint.h>
#include <vector>
#include <assert.h>

#define _ENABLE_INJECT_DEBUG 1

#define sz_align(d,a) (((d) + ((a) - 1)) & ~((a) - 1))  
#define calc_stack_size(n) sz_align((n) * 8, 16) + 8

static const auto teststacksize = calc_stack_size(4);
// 48 89 44 24 28       mov         qword ptr [rsp+28h],rax

typedef int(*RtlCreateUserThreadProc)(
    void*,					// ProcessHandle
    void*,                  // SecurityDescriptor
    DWORD64,                // CreateSuspended
    DWORD64,                // StackZeroBits
    void*,                  // StackReserved
    void*,                  // StackCommit
    void*,		            // StartAddress
    void* StartParameter,   // StartParameter
    PHANDLE,                // ThreadHandle
    void* lpClientID    // ClientID)
    );

inline
char* transcode(const wchar_t* source)
{
    // ASSERT(source != nullptr);
    auto size = WideCharToMultiByte(CP_ACP, 0, source, -1, NULL, 0, NULL, NULL);
    char* result = (char*)calloc(1, size);
    WideCharToMultiByte(CP_ACP, 0, source, -1, result, size, NULL, NULL);

    return result;
}

template<typename _Elem, typename _Fty> inline
void split(_Elem* s, const _Elem delim, const _Fty& op)
{
    _Elem* _Start = s; // the start of every string
    _Elem* _Ptr = s;   // source string iterator
    while (*_Ptr != '\0')
    {
        if (delim == *_Ptr/* && _Ptr != _Start*/)
        {
            if (_Ptr != _Start)
                if (op(_Start, _Ptr))
                    break;
            _Start = _Ptr + 1;
        }
        ++_Ptr;
    }
    if (_Start != _Ptr) {
        op(_Start, _Ptr);
    }
}

inline
void* xxalloc(HANDLE hProcess, size_t size, DWORD flProtect = PAGE_READWRITE)
{
    return VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, flProtect);
}

inline
void xxfree(HANDLE hProcess, void* p)
{
    VirtualFreeEx(hProcess, p, 0, MEM_RELEASE);
}

inline
BOOL xxwrite(HANDLE hProcess, void*p, const void* data, size_t size)
{
    return WriteProcessMemory(hProcess, p, data, size, NULL);
}

inline
void* xxmemdup(HANDLE hProcess, const void* data, size_t size, DWORD fProtect = PAGE_READWRITE)
{
    auto vmem = xxalloc(hProcess, size, fProtect);
    xxwrite(hProcess, vmem, data, size);
    return vmem;
}

char* xxstrdup(HANDLE hProcess, const char* str)
{
    return (char*)xxmemdup(hProcess, str, strlen(str) + 1);
}

wchar_t* xxwcsdup(HANDLE hProcess, const wchar_t* str)
{
    return (wchar_t*)xxmemdup(hProcess, str, (wcslen(str) + 1) << 1);
}

bool ExecuteRemoteKernelProc(HANDLE process, char* functionName, LPVOID param, DWORD& exitCode);

bool ExecuteRemoteKernelProcWithInjectCode(HANDLE hProcess, char* functionName, LPVOID param, DWORD64 param2, DWORD& exitCode);

/*

usage:
 wow64helper.exe 1 PID kernelFuncName strParam
 wow64helper.exe 2 PID kernelFuncName pvoid64_value

 #currently supported parameter types
     v; [void]
     u64; [uint64_t]
     s; [string]
     ws: [wstring]
     us; [UNICODE_STRING]
 #plan support types:
     u8,u16,u32

 @remark: all int types use reinterpret_cast, unsigned store also support signed int
 wow64helper.exe 0 PID OSModuleName ModuleProcName paramsTypes [parameters]...
 wow64helper.exe 1 PID OSModuleName ModuleProcName paramsTypes [parameters]...

example:
         WowRemoteExecuteProc64(1 string arg)         ---> wow64helper.exe 1 2332 GetModuleHandleW "x-studio365.lua.debug.x64.dll"
         WowRemoteProc64(1 integer arg)               ---> wow64helper.exe 2 2332 FreeLibrary 7393439
         WowRemoteExecuteKernelProc64(2 integer arg)  ---> wow64helper.exe 3 2332 FreeLibraryAndExitThread 7393439 0
         WowRemoteInject64                            ---> wow64helper.exe 4 2332

new example:
*/

template <class T>
struct _UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T Buffer;
};

typedef _UNICODE_STRING_T<DWORD64> UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

struct RemoteArg
{
    int type = 0; // 0: integer, 1: string, 2: wstring, 3: UNICODE_STRING
    union {
        char* valuestring;
        wchar_t* valuewstring;
        uint64_t valueint = 0;
        void* ptr;
        UNICODE_STRING* valueus;
    } value;
};

/*
 option: 0: use kernel32 CreateRemoteThread
         1: use ntdll RtlCreateUserThread RtlExitUserThread
*/
bool WowExecuteRemoteProc64(int option, HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName, wchar_t* argt, wchar_t** argv, int argc, DWORD& exitCode);

int __stdcall wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
    // MessageBox(nullptr, L"waiting for debugger to attach!", L"Tips", MB_OK);
    int ret = -1;

    auto szCmdLine = GetCommandLine();

    int argc = 0;
    auto argv = CommandLineToArgvW(szCmdLine, &argc);

    if (argc >= 6) {
        int option = wcstol(argv[1], nullptr, 10);

        DWORD dwPID = wcstoul(argv[2], nullptr, 10);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
        if (hProcess == nullptr)
            return ret;

        DWORD exitCode = 0;

        /*
        wow64helper.exe 0 PID OSModuleName ModuleProcName paramsTypes [parameters]...
        wow64helper.exe 1 PID OSModuleName ModuleProcName paramsTypes [parameters]...
        */
        bool rpcOK = WowExecuteRemoteProc64(option, hProcess, argv[3] /*moduleName*/, transcode(argv[4])/*lpProcName*/, argv[5], argv + 6, argc - 6, exitCode);

        if (rpcOK)
            ret = static_cast<int>(exitCode);

        CloseHandle(hProcess);
    }

    LocalFree(argv);
    return ret;
}

bool ExecuteRemoteKernelProc(HANDLE process, const char* functionName, LPVOID param, DWORD& exitCode)
{
    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    FARPROC function = GetProcAddress(kernelModule, functionName);

    if (function == NULL)
    {
        return false;
    }

    DWORD threadId;
    HANDLE thread = CreateRemoteThread(process, NULL, 0,
        (LPTHREAD_START_ROUTINE)function, param, 0, &threadId);

    if (thread != NULL)
    {
        WaitForSingleObject(thread, INFINITE);
        GetExitCodeThread(thread, &exitCode);

        CloseHandle(thread);
        return true;
    }
    else
    {
        return false;
    }
}

bool ExecuteRemoteKernelProcWithInjectCode(HANDLE hProcess, const char* functionName, LPVOID param, DWORD64 param2, DWORD& exitCode)
{
    unsigned char rpc_thunk_code[] = {
#if _ENABLE_INJECT_DEBUG
        0xCC,
#endif
        // 0x48, 0x83, 0xEC, 0x28,                                  // sub         rsp,28h;
        0x48, 0xB8, 0x21, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // mov         rax,2222222222222221h
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rdx,1122334455667782h
        // 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov      rcx,1122334455667781h, rcx is ThreadProc(void*)
        0x48, 0xFF, 0xE0,                                           // jmp         rax;
                                                                                                                                // 0xFF, 0xD0,                                                 // call        rax; The Remote Proc, 
                                                                                                                                // 0x48, 0x83, 0xC4, 0x28,                                  // add         rsp, 28h
                                                                                                                                // 0xC3,                                                    // ret; jmp         rax
    };

    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    FARPROC function = GetProcAddress(kernelModule, functionName);

    if (function == NULL)
    {
        return false;
    }

    auto  shell_code_addr = VirtualAllocEx(hProcess, NULL, sizeof(rpc_thunk_code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!shell_code_addr)
    {
        return FALSE;
    }
    memcpy(rpc_thunk_code + 6 + _ENABLE_INJECT_DEBUG - 4, &function, sizeof(DWORD64));
    memcpy(rpc_thunk_code + 16 + _ENABLE_INJECT_DEBUG - 4, &param2, sizeof(DWORD64));

    WriteProcessMemory(hProcess, shell_code_addr, rpc_thunk_code, sizeof(rpc_thunk_code), nullptr);

    DWORD threadId;
    HANDLE thread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)shell_code_addr, param, 0, &threadId);

    if (thread != NULL)
    {
        WaitForSingleObject(thread, INFINITE);
        GetExitCodeThread(thread, &exitCode);
        VirtualFreeEx(hProcess, shell_code_addr, 0, MEM_RELEASE);

        CloseHandle(thread);
        return true;
    }
    else
    {
        VirtualFreeEx(hProcess, shell_code_addr, 0, MEM_RELEASE);
        return false;
    }
}

bool rpcall1(int option, HANDLE hProcess, void* procAddress, void* param, DWORD& exitCode)
{
    if (option == 0) {
        DWORD threadId;
        HANDLE thread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)procAddress, param, 0, &threadId);

        exitCode = 0;
        if (thread != NULL)
        {
            WaitForSingleObject(thread, INFINITE);
            GetExitCodeThread(thread, &exitCode);

            CloseHandle(thread);
            return true;
        }
        else
        {
            return false;
        }
    }
    else {
        return false;
    }
}

bool WowExecuteRemoteProc64(int option, HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName, wchar_t* argt, wchar_t** argv, int argc, DWORD& exitCode)
{ // FOR API: CreateRemoteThread
    if (option != 0 && option != 1)
        return false; // Invalid option

    HMODULE hModule = GetModuleHandleW(lpModuleName);
    if (hModule == nullptr)
        return false;
    FARPROC procAddress = GetProcAddress(hModule, lpProcName);
    if (procAddress == nullptr)
        return false;

    int formatc = 0;
    if (argc == 0)
        return false;

    std::vector<RemoteArg> args;
    bool result = true;
    split(argt, L';', [&](wchar_t* s, wchar_t* e) {
        if (formatc >= argc)
            return true; // break if arguments insufficient 

        auto n = e - s;

        /*
        #currently supported parameter types
        v; [void]
        s; [s]
        u64; [uint64_t]
        us; [UNICODE_STRING]
        */
        auto temp = s[n];
        s[n] = L'\0';
        RemoteArg remoteArg;
        if (wcscmp(s, L"u64") == 0)
        {
            remoteArg.type = 0;
            remoteArg.value.valueint = wcstoull(argv[formatc], nullptr, 10);
        }
        else if (wcscmp(s, L"s") == 0)
        {
            remoteArg.type = 1;
            auto string = transcode(argv[formatc]);
            remoteArg.value.valuestring = xxstrdup(hProcess, string);
            free(string);
        }
        else if (wcscmp(s, L"ws") == 0)
        {
            remoteArg.type = 2;
            remoteArg.value.valuewstring = xxwcsdup(hProcess, argv[formatc]);
        }
        else if (wcscmp(s, L"us") == 0)
        {
            remoteArg.type = 3;

            char* struc = (char*)xxalloc(hProcess, sizeof(UNICODE_STRING));

            WORD length = static_cast<WORD>(wcslen(argv[formatc]));
            auto bytes = (length + 1) * 2;
            auto rbuffer = xxalloc(hProcess, (length + 1) * 2);

            xxwrite(hProcess, struc + offsetof(UNICODE_STRING, Length), &length, 2);
            xxwrite(hProcess, struc + offsetof(UNICODE_STRING, MaximumLength), &length, 2);
            xxwrite(hProcess, struc + offsetof(UNICODE_STRING, Buffer), &rbuffer, sizeof(rbuffer));

            xxwrite(hProcess, rbuffer, argv[formatc], bytes);
        }
        else {
            // error
            result = false;
            return true;
        }

        s[n] = temp;
        ++formatc;

        args.push_back(remoteArg);

        return false;
    });
    /*
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov         rcx,0; no need, cross transport

    The second operand MAX bytes is: 4Bytes
    Add & Sub rsp
    48 83 EC 20          sub         rsp,20h    1B
    48 81 EC 20 11 00 00 sub         rsp,1120h  4B

    48 83 C4 20          add         rsp,20h    1B
    48 81 C4 20 11 00 00 add         rsp,1120h  4B

    mov      qword ptr [rsp+?],rax, 1B or 4B
    48 89 84 24 + ?
    */
    /*
    unsigned char inject_thunk_code1[] = {
    #if _ENABLE_INJECT_DEBUG
    0xCC,
    #endif
    0x48, 0x83, 0xEC, 0x28,                                         // sub         rsp,28h ; 4 parameters + ret address = 4 * 8 + 8 = 40 = 28h
    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov         r9,0
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov         r8,0
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov         rdx,0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov         rax,0; Address of LdrLoadDll
    0x48, 0xFF, 0xE0,                                               // jmp         rax; jmp to LdrLoadDll
    0x19, 0x88, 0x12, 0x19                                          // MAGIC 19881219
    };
    unsigned char inject_thunk_code2[] = {
    #if _ENABLE_INJECT_DEBUG
    0xCC,
    #endif
    0x48, 0x83, 0xEC, 0x28,                                     // sub         rsp,28h ; 4 parameters + ret address = 4 * 8 + 8 = 40 = 28h
    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         r9,1122334455667784h
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         r8,1122334455667783h
    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rdx,0
    // 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rcx,0; no need, cross transport
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rax,1111111111111111h; Address of LdrLoadDll
    0xFF, 0xD0,                                                 // call        rax; call LdrLoadDll
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rax,2222222222222222h; Address of RtlExitUserThread
    0x33, 0xC9,                                                 // xor         ecx,ecx; exit code: 0
    0x48, 0x83, 0xC4, 0x28,                                     // add         rsp,28h
    0x48, 0xFF, 0xE0,                                           // jmp         rax; jmp to RtlExitUserThread
    0x19, 0x88, 0x12, 0x19                                      // MAGIC 19881219
    */

    if (option == 0) {
        // should use ret instruction
        const unsigned char rpc_thunk_code_template[] = {
    #if _ENABLE_INJECT_DEBUG
            0xCC,
    #endif
            0x48, 0x83, 0xEC, 0x28,                                         // sub         rsp,28h ; 4 parameters + ret address = 4 * 8 + 8 = 40 = 28h
            //0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov         r9,0
            //0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov         r8,0
            //0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov         rdx,0
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov         rax,0; The remote Proc

            0xFF, 0xD0/* call rax */,// 0x48, 0xFF, 0xE0,        // jmp         rax; jmp to LdrLoadDll

            0x48, 0x83, 0xC4, 20, // add rsp, 28
            0xC3, // ret
            0x19, 0x88, 0x12, 0x19                                          // MAGIC 19881219
        };

        if (formatc > 1) { // The first parameter transfer by ThreadProc(void*/*rcx*/);
            if (formatc <= 4) { // argc = [2, 4]
                auto thunkSize = sizeof(rpc_thunk_code_template) + 10 * (formatc - 1);
                auto stackNeeded = calc_stack_size(formatc);

                auto thunkLocal = (unsigned char*)calloc(1, thunkSize);
                auto ptr = thunkLocal;
#if _ENABLE_INJECT_DEBUG
                *ptr++ = 0xCC;
#endif
                // sub rsp, stackNeeded;
                *ptr++ = 0x48;
                *ptr++ = 0x83;
                *ptr++ = 0xEC;
                *ptr++ = static_cast<uint8_t>(stackNeeded);

                // mov rdx, ?; 2nd arg
                *(uint16_t*)ptr = 0xBA48, ptr += sizeof(uint16_t);
                *(uint64_t*)ptr = args[1].value.valueint, ptr += sizeof(uint64_t);
                if (formatc > 2) {
                    // mov r8, ?; 3rd arg
                    *(uint16_t*)ptr = 0xB849, ptr += sizeof(uint16_t);
                    *(uint64_t*)ptr = args[2].value.valueint, ptr += sizeof(uint64_t);
                    if (formatc > 3) {
                        // mov r9, ? 4th arg
                        *(uint16_t*)ptr = 0xB949, ptr += sizeof(uint16_t);
                        *(uint64_t*)ptr = args[3].value.valueint, ptr += sizeof(uint64_t);
                    }
                }

                // mov rax, ?; Address of The function
                *(uint16_t*)ptr = 0xB848, ptr += sizeof(uint16_t);
                *(uint64_t*)ptr = reinterpret_cast<uint64_t>(procAddress), ptr += sizeof(uint64_t);

                // jmp rax;
#if 0
                * ptr++ = 0x48;
                *ptr++ = 0xFF;
                *ptr++ = 0xE0;
#endif
                // call rax
                *ptr++ = 0xFF;
                *ptr++ = 0xD0;

                // 0x48, 0x83, 0xC4, 20, // add rsp, 28
                *ptr++ = 0x48;
                *ptr++ = 0x83;
                *ptr++ = 0xC4;
                *ptr++ = static_cast<uint8_t>(stackNeeded);

                // ret
                *ptr++ = 0xC3;


                // write MAGIC
                *(uint32_t*)ptr = 0x19128819, ptr += sizeof(uint32_t);

                assert(ptr - thunkLocal == thunkSize);
                auto finalThunkCode = xxmemdup(hProcess, thunkLocal, thunkSize, PAGE_EXECUTE_READWRITE);

                result = rpcall1(option, hProcess, finalThunkCode, args[0].value.ptr, exitCode);

                free(thunkLocal);
            }
            else { // > 4 parameters
            }
        }
        else {
            // No thunk code needed, call directly
            result = rpcall1(option, hProcess, procAddress, args[0].value.ptr, exitCode);
        }
    }
    else { // RtlCreateUserThread + RtlExitUserThread
        const unsigned char rpc_thunk_code_template[] = {
#if _ENABLE_INJECT_DEBUG
            0xCC,
#endif
            0x48, 0x83, 0xEC, 0x28,                                         // sub         rsp,28h ; 4 parameters + ret address = 4 * 8 + 8 = 40 = 28h
            // 0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov         r9,0
            // 0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov         r8,0
            // 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov         rdx,0
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov         rax,0; The remote Proc
            0xFF, 0xD0,                                                 // call        rax; call LdrLoadDll
            0x48, 0x83, 0xC4, 0x28,                                     // add         rsp,28h
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rax,2222222222222222h; Address of RtlExitUserThread
        };
        const unsigned char rpc_thunk_code_exit[] = {
            0x33, 0xC9,                                                 // xor         ecx,ecx; exit code: 0
            0x48, 0xFF, 0xE0,                                           // jmp         rax; jmp to RtlExitUserThread
            0x19, 0x88, 0x12, 0x19                                      // MAGIC 19881219
        };

        auto thunkSize = sizeof(rpc_thunk_code_template) + sizeof(rpc_thunk_code_template) + 10 * (formatc - 1);
        auto stackNeeded = calc_stack_size(formatc);

        auto thunkLocal = (unsigned char*)calloc(1, thunkSize);
        auto ptr = thunkLocal;
#if _ENABLE_INJECT_DEBUG
        *ptr++ = 0xCC;
#endif
        // sub rsp, stackNeeded;
        *ptr++ = 0x48;
        *ptr++ = 0x83;
        *ptr++ = 0xEC;
        *ptr++ = static_cast<uint8_t>(stackNeeded);

        // mov rdx, ?; 2nd arg
        *(uint16_t*)ptr = 0xBA48, ptr += sizeof(uint16_t);
        *(uint64_t*)ptr = args[1].value.valueint, ptr += sizeof(uint64_t);
        if (formatc > 2) {
            // mov r8, ?; 3rd arg
            *(uint16_t*)ptr = 0xB849, ptr += sizeof(uint16_t);
            *(uint64_t*)ptr = args[2].value.valueint, ptr += sizeof(uint64_t);
            if (formatc > 3) {
                // mov r9, ? 4th arg
                *(uint16_t*)ptr = 0xB949, ptr += sizeof(uint16_t);
                *(uint64_t*)ptr = args[3].value.valueint, ptr += sizeof(uint64_t);
            }
        }

        // mov rax, ?; Address of The function
        *(uint16_t*)ptr = 0xB848, ptr += sizeof(uint16_t);
        *(uint64_t*)ptr = reinterpret_cast<uint64_t>(procAddress), ptr += sizeof(uint64_t);

        // call rax
        *ptr++ = 0xFF;
        *ptr++ = 0xD0;

        // 0x48, 0x83, 0xC4, 20, // add rsp, 28
        *ptr++ = 0x48;
        *ptr++ = 0x83;
        *ptr++ = 0xC4;
        *ptr++ = static_cast<uint8_t>(stackNeeded);

        auto ntdll = GetModuleHandle(L"ntdll.dll");
        auto RtlExitUserThread = GetProcAddress(ntdll, "RtlExitUserThread");

        // RtlUserExitThread
        *(uint16_t*)ptr = 0xB848, ptr += sizeof(uint16_t);
        *(uint64_t*)ptr = reinterpret_cast<uint64_t>(RtlExitUserThread), ptr += sizeof(uint64_t);

#if 0
        // jmp rax;
        *ptr++ = 0x48;
        *ptr++ = 0xFF;
        *ptr++ = 0xE0;

        // write MAGIC
        *(uint32_t*)ptr = 0x19128819, ptr += sizeof(uint32_t);
#endif
        memcpy(ptr, rpc_thunk_code_exit, sizeof(rpc_thunk_code_exit)), ptr += sizeof(rpc_thunk_code_exit);

        assert(ptr - thunkLocal == thunkSize);
        auto finalThunkCode = xxmemdup(hProcess, thunkLocal, thunkSize, PAGE_EXECUTE_READWRITE);

        auto RtlCreateUserThread = (RtlCreateUserThreadProc)GetProcAddress(ntdll, "RtlCreateUserThread");

        struct {
            DWORD64 UniqueProcess;
            DWORD64 UniqueThread;
        } clientId;

        HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
        int ret = RtlCreateUserThread(
            hProcess,				 // ProcessHandle
            nullptr,                 // SecurityDescriptor
            (DWORD64)FALSE,          // CreateSuspended
            (DWORD64)0,              // StackZeroBits
            nullptr,                 // StackReserved
            nullptr,                 // StackCommit
            finalThunkCode,	         // StartAddress
            nullptr,                 // StartParameter
            &hRemoteThread,          // ThreadHandle
            &clientId);              // ClientID)

        if (INVALID_HANDLE_VALUE != hRemoteThread)
        {
            WaitForSingleObject(hRemoteThread, INFINITE);
        }
        else {
            result = false;
        }

        // TODO: free memory
        free(thunkLocal);
    }

    return result;
}

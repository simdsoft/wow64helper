#include <Windows.h>
#include <Shlwapi.h>
#include <ShellAPI.h>
#include <stdint.h>
#include <list>

#define _ENABLE_INJECT_DEBUG 0

#define sz_align(d,a) (((d) + ((a) - 1)) & ~((a) - 1))  
#define calc_stack_size(n) sz_align((n) * 8, 16) + 8

static const auto teststacksize = calc_stack_size(4);
// 48 89 44 24 28       mov         qword ptr [rsp+28h],rax
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
void* valloc(HANDLE hProcess, size_t size)
{
    return VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

inline
void vfree(HANDLE hProcess, void* p)
{
    VirtualFreeEx(hProcess, p, 0, MEM_RELEASE);
}

inline
void* vmemdup(HANDLE hProcess, const void* data, size_t size)
{
    auto vmem = valloc(hProcess, size);
    vwrite(vmem, vmem, data, size);
    return vmem;
}

inline
BOOL vwrite(HANDLE hProcess, void*p, const void* data, size_t size)
{
    return WriteProcessMemory(hProcess, p, data, size, NULL);
}

char* strdup(HANDLE hProcess, const char* str)
{
    auto size = (strlen(str) + 1);
    auto rdata = valloc(hProcess, size);
    vwrite(hProcess, rdata, str, size);
    return (char*)rdata;
}

wchar_t* wcsdup(HANDLE hProcess, const wchar_t* str)
{
    auto size = (wcslen(str) + 1) << 1;
    auto rdata = valloc(hProcess, size);
    vwrite(hProcess, rdata, str, size);
    return (wchar_t*)rdata;
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
        UNICODE_STRING* valueus;
    } value;
};

bool WowExecuteRemoteProc64_V1(HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName, wchar_t* argt, wchar_t** argv, int argc, DWORD& exitCode);
bool WowExecuteRemoteProc64_V2(HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName, wchar_t* argt, wchar_t** argv, int argc, DWORD& exitCode);

bool WowInject64(HANDLE hProcess, const wchar_t* lpModuleName, char* lpProcName, const wchar_t* argt, const wchar_t** argv, int argc, DWORD& exitCode);

bool ConstructThunkCode(HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName, wchar_t* argt, wchar_t** argv, int argc, char*& thunkCode, std::list<RemoteArg>& args);

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

        bool rpcOK = false;
        /*
        wow64helper.exe 0 PID OSModuleName ModuleProcName paramsTypes [parameters]...
        wow64helper.exe 1 PID OSModuleName ModuleProcName paramsTypes [parameters]...
        */
        switch (option) {
        case 0:
            rpcOK = WowExecuteRemoteProc64_V1(hProcess, argv[3] /*moduleName*/, transcode(argv[4])/*lpProcName*/, argv[5], argv + 6, argc - 6, exitCode);
            break;
        case 1:
            ; // rpcOK = WowExecuteRemoteProc64_V2(hProcess, argv[3] /*moduleName*/, transcode(argv[4])/*lpProcName*/, argv[5], argv + 6, argc - 6, exitCode);
            break;
        default:;
        }
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

bool WowExecuteRemoteProc64_V1(HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName,  wchar_t* argt, wchar_t** argv, int argc, DWORD& exitCode)
{
    std::list<RemoteArg> args;
    char* thunkCode = nullptr;
    ConstructThunkCode(hProcess, lpModuleName, lpProcName, argt, argv, argc, thunkCode, args);
    return true;
}

bool ConstructThunkCode(HANDLE hProcess, wchar_t* lpModuleName, char* lpProcName, wchar_t* argt, wchar_t** argv, int argc, char*& thunkCode, std::list<RemoteArg>& args)
{ // FOR API: CreateRemoteThread
    thunkCode = nullptr;

    int formatc = 0;
    if (argc == 0)
        return false;

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
            remoteArg.value.valuestring = strdup(hProcess, string);
            free(string);
        }
        else if (wcscmp(s, L"ws") == 0)
        {
            remoteArg.type = 2;
            remoteArg.value.valuewstring = wcsdup(hProcess, argv[formatc]);
        }
        else if (wcscmp(s, L"us") == 0)
        {
            remoteArg.type = 3;

            char* struc = (char*)valloc(hProcess, sizeof(UNICODE_STRING));

            WORD length = static_cast<WORD>(wcslen(argv[formatc]));
            auto bytes = (length + 1) * 2;
            auto rbuffer = valloc(hProcess, (length + 1) * 2);

            vwrite(hProcess, struc + offsetof(UNICODE_STRING, Length), &length, 2);
            vwrite(hProcess, struc + offsetof(UNICODE_STRING, MaximumLength), &length, 2);
            vwrite(hProcess, struc + offsetof(UNICODE_STRING, Buffer), &rbuffer, sizeof(rbuffer));

            vwrite(hProcess, rbuffer, argv[formatc], bytes);
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
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rdx,0
    // 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rcx,0; no need, cross transport
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rax,1111111111111111h; Address of LdrLoadDll
    0xFF, 0xD0,                                                 // call        rax; call LdrLoadDll
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rax,2222222222222222h; Address of RtlExitUserThread
    0x33, 0xC9,                                                 // xor         ecx,ecx; exit code: 0
    0x48, 0x83, 0xC4, 0x28,                                     // add         rsp,28h
    0x48, 0xFF, 0xE0,                                           // jmp         rax; jmp to RtlExitUserThread
    0x19, 0x88, 0x12, 0x19                                      // MAGIC 19881219
    */

    const unsigned template_thunk_code1[] = {
#if _ENABLE_INJECT_DEBUG
        0xCC,
#endif
        0x48, 0x83, 0xEC, 0x28,                                         // sub         rsp,28h ; 4 parameters + ret address = 4 * 8 + 8 = 40 = 28h
        //0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov         r9,0
        //0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov         r8,0
        //0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov         rdx,0
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov         rax,0; Address of LdrLoadDll
        0x48, 0xFF, 0xE0,                                               // jmp         rax; jmp to LdrLoadDll
        0x19, 0x88, 0x12, 0x19                                          // MAGIC 19881219
    };

    if (formatc > 1) { // The first parameter transfer by ThreadProc(void*/*rax*/);

        ptrdiff_t offset = 0;

        if (formatc <= 4) { // argc = [2, 4]
            auto thunkSize = sizeof(template_thunk_code1) + 10 * (formatc - 1);
            auto stackNeeded = calc_stack_size(formatc);
            if (stackNeeded > 256) {
                thunkSize += 3; // sub rsp instruction size change from 4B to 7B
            }

            auto tclocal = (unsigned char*)calloc(1, thunkSize);
#if _ENABLE_INJECT_DEBUG
            *tclocal++ = 0xCC;
#endif
            if (stackNeeded <= 256) {
                // 48 83 EC
                *tclocal++ = 0x48;
                *tclocal++ = 0x83;
                *tclocal++ = 0xEC;
                *tclocal++ = static_cast<uint8_t>(stackNeeded);
            }
            else {
                // 48 83 EC
                *tclocal++ = 0x48;
                *tclocal++ = 0x81;
                *tclocal++ = 0xEC;
                *(uint32_t*)tclocal = stackNeeded, tclocal += sizeof(uint32_t);
            }
        }
        else {

        }
    }
    else {
        // No thunk code needed.
    }


    return result;
}

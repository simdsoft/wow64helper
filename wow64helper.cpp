#include <Windows.h>
#include <Shlwapi.h>
#include <ShellAPI.h>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

#define _ENABLE_INJECT_DEBUG 0

static
bool ExecuteRemoteKernelProcWithInjectCode(HANDLE hProcess, const char* functionName, LPVOID param, DWORD64 param2, DWORD& exitCode)
{
    unsigned char rpc_thunk_code[] = {
#if _ENABLE_INJECT_DEBUG
        0xCC,
#endif
        // 0x48, 0x83, 0xEC, 0x28,                                     // sub         rsp,30h;
        0x48, 0xB8, 0x21, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // mov         rax,2222222222222221h
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rdx,1122334455667782h
                                                                    // 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov         rcx,1122334455667781h, rcx is ThreadProc(void*)
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

static
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

/*

usage:
 wow64helper.exe 1 PID kernelFuncName strParam
 wow64helper.exe 2 PID kernelFuncName pvoid64_value

example: 
         WowRemoteExecuteKernelProc64(1 string arg)    ---> wow64helper.exe 1 2332 GetModuleHandleW "x-studio365.lua.debug.x64.dll"
         WowRemoteExecuteKernelProc64(1 integer arg)  ---> wow64helper.exe 2 2332 FreeLibrary 7393439
         WowRemoteExecuteKernelProc64(2 integer arg)  ---> wow64helper.exe 3 2332 FreeLibraryAndExitThread 7393439 0
         WowRemoteInject64                                            ---> wow64helper.exe 4 2332
*/
int __stdcall wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
    // MessageBox(nullptr, L"waiting for debugger to attach!", L"Tips", MB_OK);
    int ret = 0;

    auto szCmdLine = GetCommandLine();

    int argc = 0;
    auto argv = CommandLineToArgvW(szCmdLine, &argc);

    if (argc >= 5) {
        int option = wcstol(argv[1], nullptr, 10);

        DWORD dwPID = wcstoul(argv[2], nullptr, 10);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
        if (hProcess == nullptr)
            return ret;

        std::string funcName;
        int buffersize = WideCharToMultiByte(CP_ACP, 0, argv[3], -1, NULL, 0, NULL, NULL);
        funcName.resize(buffersize - 1);
        WideCharToMultiByte(CP_ACP, 0, argv[3], -1, &funcName.front(), buffersize, NULL, NULL);

        DWORD exitCode = 0;
        if (option == 1) {
            std::wstring strParam = argv[4];
            void* strRemote = VirtualAllocEx(hProcess, NULL, (strParam.size() + 1) << 1, MEM_COMMIT, PAGE_READWRITE);
            if (strRemote != nullptr) {
                if (WriteProcessMemory(hProcess, strRemote, strParam.c_str(), (strParam.size() + 1) << 1, NULL) &&
                    ExecuteRemoteKernelProc(hProcess, funcName.c_str(), strRemote, exitCode))
                {
                    ret = (exitCode != 0) ? 1 : 0; // 1: specificed module loaded, 0: no specified module loaded.
                }

                VirtualFreeEx(hProcess, strRemote, 0, MEM_RELEASE);
            }
        }
        else if (option == 2) {
            void* lpParam = reinterpret_cast<void*>(wcstoll(argv[4], nullptr, 10));
            if (lpParam != nullptr) {
                if (ExecuteRemoteKernelProc(hProcess, funcName.c_str(), lpParam, exitCode))
                {
                    ret = (exitCode != 0) ? 1 : 0; // 1: specificed module loaded, 0: no specified module loaded.
                }
            }
        }
        else if (option == 3) {
            void* lpParam = reinterpret_cast<void*>(wcstoll(argv[4], nullptr, 10));
            DWORD64 param2 = 0;
            if(argc >= 6)
                param2 = wcstol(argv[5], nullptr, 10);
            if (lpParam != nullptr) {
                if (ExecuteRemoteKernelProcWithInjectCode(hProcess, funcName.c_str(), lpParam, param2, exitCode))
                {
                    ret = (exitCode != 0) ? 1 : 0; // 1: specificed module loaded, 0: no specified module loaded.
                }
            }
        }

        CloseHandle(hProcess);
    }

    LocalFree(argv);
    return ret;
}

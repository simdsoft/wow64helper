# wow64helper  

## Usage:  
   wow64helper.exe Option PID OSModuleName ModuleProcName paramsTypes [parameters]...  
  
## Option:  
   - 0: CreateRemoteThread, 
   - 1: RtlCreateUserThread + RtlExitUserThread  
  
## paramsTypes:  
   - uptr --> uintptr_t or nullptr  
   - s -->     string, could be placeholder for ```PHANDLE``` such as ```0000``` for 32bit, ```00000000``` for 64bit
   - ws -->   wstring  
   - us -->    UNICODE_STRING  
  
## examples:

- option=0: 0 13220 kernel.dll LoadLibraryW ws D:\dummy.dll  
- option=1
  - x64: 1 13220 ntdll.dll LdrLoadDll uptr;uptr;us;s 0 0 D:\dummy.dll 00000000  
  - x86: 1 13220 ntdll.dll LdrLoadDll uptr;uptr;us;s 0 0 D:\dummy.dll 0000

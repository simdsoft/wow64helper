#wow64helper  
Usage: 
   wow64helper.exe Option PID OSModuleName ModuleProcName paramsTypes [parameters]...  
  
Option:  
   0: CreateRemoteThread, 1: RtlCreateUserThread + RtlExitUserThread  
  
paramsTypes:  
   u64 --> uint64_t or nullptr  
   s -->     string  
   ws -->   wstring  
   us -->    UNICODE_STRING  
  
examples:
   0 13220 kernel.dll LoadLibraryW ws D:\dummy.dll  
   1 13220 ntdll.dll LdrLoadDll u64;u64;us;s 0 0 D:\dummy.dll 12345678

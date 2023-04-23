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
    var messageID:uint64 = 0
    var treeID:array[4,byte]
    var sessionID:array[8,byte]
    if(optionsStruct.Domain != ""):
        optionsStruct.Username = optionsStruct.Domain & "\\" & optionsStruct.Username
    var targetBytesInWCharForm:WideCStringObj = newWideCString(optionsStruct.Target) # .len property doesn't count its double null bytes, and it doesn't represent byte array length
    var tcpSocket:net.Socket = newSocket(buffered=false)
    try:
        tcpSocket.connect(optionsStruct.Target,Port(445),60000)
    except CatchableError:
        var e = getCurrentException()
        var msg = getCurrentExceptionMsg()
        echo "[!] Got exception ", repr(e), " with message ", msg
        quit(0)
    if(optionsStruct.IsVerbose):
        echo "[+] Connected to ", optionsStruct.Target, ":445"
    if(NegotiateSMB2(tcpSocket,addr messageID,addr treeID, addr sessionID)):
        messageID+=1
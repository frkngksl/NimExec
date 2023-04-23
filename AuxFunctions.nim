import system
import net

proc SendAndReceiveFromSocket*(socket:net.Socket,sentBytes:ptr seq[byte]):(array[5096,byte],int) =
    var returnBytes:array[5096,byte]
    var tempBytes:array[5096,byte]
    var tempIntArray:array[4,byte] = [byte 0x00,0x00,0x00,0x00]
    var received:int = 0
    var index:int = 0
    var expectedSize:int = 0
    var sentSize:int = 0

    try:
        sentSize = socket.send(addr ((sentBytes[])[0]),(sentBytes[]).len)
        if(sentSize != sentBytes[].len):
            echo "[!] Error on socket write!"
            quit(0)
        received += socket.recv(addr returnBytes[0],5096)
        if(received < 0):
            echo "[!] Error on socket read!"
            quit(0)
        tempIntArray[0] = returnBytes[3]
        tempIntArray[1] = returnBytes[2]
        tempIntArray[2] = returnBytes[1]
        tempIntArray[3] = 0
        expectedSize = (cast[ptr int](addr tempIntArray[0]))[] + 4 # Netbios header length
        while(expectedSize > received):
            index = received
            received += socket.recv(addr tempBytes[0],5096)
            copyMem(addr(returnBytes[index]),addr(tempBytes[0]),received)
    
    except CatchableError:
        var e = getCurrentException()
        var msg = getCurrentExceptionMsg()
        echo "[!] Got exception ", repr(e), " with message ", msg
        quit(0)
    return (returnBytes,expectedSize)
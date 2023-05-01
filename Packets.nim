import net
import ptr_math
import hostname
import sequtils
import std/endians
import std/strutils
import std/sysrand
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


proc CreateRequest*(socket: net.Socket,options:ptr OPTIONS, messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
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
        return true
    else:
        return false


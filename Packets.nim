import net
import ptr_math
import hostname
import sequtils
import std/endians
import std/strutils
import std/sysrand
import Structs
import AuxFunctions

#         public static OrderedDictionary SMB2Header(byte[] packet_command, int packet_message_ID, byte[] packet_tree_ID, byte[] packet_session_ID)

proc NetBiosFiller(packetLength:int): NetBiosHeader = 
    var tempPointer: ptr byte = cast[ptr byte](unsafeAddr packetLength)
    var lengthArray: array[3,byte] = [(tempPointer+2)[],(tempPointer+1)[],(tempPointer)[]]
    var returnStruct:NetbiosHeader
    returnStruct.MessageType = 0x00
    returnStruct.Length = lengthArray
    return returnStruct


proc SMB2HeaderFiller(packetCommand:uint16,creditCharge:uint16,creditsRequested:uint16,messageID:uint64,treeID: array[4,byte],sessionID: array[8,byte]):SMB2Header =
    var returnStruct:SMB2Header
    returnStruct.ProtocolID = [ byte 0xfe, 0x53, 0x4d, 0x42 ]
    returnStruct.HeaderLength = 64
    returnStruct.CreditCharge = creditCharge
    returnStruct.ChannelSequence = 0
    returnStruct.Reserved = 0
    returnStruct.Command = packetCommand
    returnStruct.CreditsRequested = creditsRequested
    returnStruct.Flags = 0
    returnStruct.ChainOffset = 0
    returnStruct.MessageID = messageID
    returnStruct.ProcessID = 0
    returnStruct.TreeID = treeID
    returnStruct.SessionID = sessionID
    returnStruct.Signature = [byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
    return returnStruct


proc SMB2NegotiateFiller():SMB2NegotiateRequest = 
    var returnStruct:SMB2NegotiateRequest
    returnStruct.StructureSize = 36
    returnStruct.DialectCount = 2
    returnStruct.SecurityMode = 1
    returnStruct.Reserved1 = 0
    returnStruct.Capabilities = [byte 0x45, 0x00, 0x00, 0x00]
    returnStruct.ClientGUID = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.NegotiateContextOffset = 0
    returnStruct.NegotiateContextCount = 0
    returnStruct.Reserved2 = 0
    returnStruct.Dialect1 = [byte 0x02, 0x02]
    returnStruct.Dialect2 = [byte 0x10, 0x02]
    return returnStruct

proc NTLMSSPNegotiateFiller(negotiateFlags:seq[byte]):NTLMSSPNegotiate = 
    var returnStruct:NTLMSSPNegotiate
    returnStruct.InitialContextTokenID = 0x60
    returnStruct.InitialContextTokenLength = 64
    returnStruct.ThisMechID = 0x06
    returnStruct.ThisMechLength = 0x06
    returnStruct.OID = [byte 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]
    returnStruct.InnerContextTokenID = 0xa0
    returnStruct.InnerContextTokenLength = 54
    returnStruct.InnerContextTokenID2 = 0x30
    returnStruct.InnerContextTokenLength2 = 52
    returnStruct.MechTypesID = 0xa0
    returnStruct.MechTypesLength = 0x0e
    returnStruct.MechTypesID2 = 0x30
    returnStruct.MechTypesLength2 = 0x0c
    returnStruct.MechTypesID3 = 0x06
    returnStruct.MechTypesLength3 = 0x0a
    returnStruct.MechType = [byte 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    returnStruct.MechTokenID = 0xa2
    returnStruct.MechTokenLength = 34
    returnStruct.NTLMSSPID = 0x04
    returnStruct.NTLMSSPLength = 32
    returnStruct.Identifier = [byte 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]
    returnStruct.MessageType = [byte  0x01, 0x00, 0x00, 0x00]
    returnStruct.NegotiateFlags = [byte negotiateFlags[0],negotiateFlags[1],negotiateFlags[2],negotiateFlags[3]]
    returnStruct.CallingWorkstationDomain = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.CallingWorkstationName = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    return returnStruct

proc SessionSetupHeaderFiller(blobLength:uint16):SessionSetupHeader =
    var returnStruct:SessionSetupHeader
    returnStruct.StructureSize = 25
    returnStruct.Flags = 0
    returnStruct.SecurityMode = 1
    returnStruct.Capabilities = [byte 0x01,0x00,0x00,0x00]
    returnStruct.Channel = [byte 0x00,0x00,0x00,0x00]
    returnStruct.BlobOffset = 0x58
    returnStruct.BlobLength = blobLength
    returnStruct.PreviousSessionId = [byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
    return returnStruct

proc NTLMSSPAuthFiller(ntlmSSPResponseLength:int):NTLMSSPAuth = 
    var returnStruct:NTLMSSPAuth
    var packetNTLMSSPLengthValue:uint32 = cast[uint32](ntlmSSPResponseLength) 
    var packetNTLMSSPLengthBytes:array[2,byte] = [byte ((cast[ptr byte](unsafeaddr(packetNTLMSSPLengthValue))+1)[]),(cast[ptr byte](unsafeaddr(packetNTLMSSPLengthValue)))[] ] 
    var packetASNLength1Value:uint32 = cast[uint32](ntlmSSPResponseLength+12) 
    var packetASNLength1Bytes:array[2,byte] = [byte ((cast[ptr byte](unsafeaddr(packetASNLength1Value))+1)[]),(cast[ptr byte](unsafeaddr(packetASNLength1Value)))[] ]
    var packetASNLength2Value:uint32 = cast[uint32](ntlmSSPResponseLength+8) 
    var packetASNLength2Bytes:array[2,byte] = [byte ((cast[ptr byte](unsafeaddr(packetASNLength2Value))+1)[]),(cast[ptr byte](unsafeaddr(packetASNLength2Value)))[] ]
    var packetASNLength3Value:uint32 = cast[uint32](ntlmSSPResponseLength+4) 
    var packetASNLength3Bytes:array[2,byte] = [byte ((cast[ptr byte](unsafeaddr(packetASNLength3Value))+1)[]),(cast[ptr byte](unsafeaddr(packetASNLength3Value)))[] ] 
    
    returnStruct.NTLMSSPAuthASNID = [byte 0xa1,0x82]
    returnStruct.NTLMSSPAuthASNLength = packetASNLength1Bytes
    returnStruct.NTLMSSPAuth_ASNID2 = [byte 0x30, 0x82 ]
    returnStruct.NTLMSSPAuth_ASNLength2 = packetASNLength2Bytes
    returnStruct.NTLMSSPAuth_ASNID3 = [byte 0xa2, 0x82 ]
    returnStruct.NTLMSSPAuth_ASNLength3 = packetASNLength3Bytes
    returnStruct.NTLMSSPAuthNTLMSSPID = [byte 0x04, 0x82 ]
    returnStruct.NTLMSSPAuthNTLMSSPLength = packetNTLMSSPLengthBytes
    return returnStruct

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


proc NTLMSSPNegotiateSMB2*(socket: net.Socket,options:ptr OPTIONS,smbNegotiateFlags:seq[byte],smbSessionKeyLengthBytes:seq[byte], messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
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





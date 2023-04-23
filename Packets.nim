import net
import ptr_math
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

proc NTLMSSPNegotiateFiller(negotiateFlags:array[4,byte]):NTLMSSPNegotiate = 
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
    returnStruct.NegotiateFlags = negotiateFlags
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

proc NTLMSSPNegotiateSMB2*(socket: net.Socket,negotiateFlags:array[4,byte], messageID:ptr uint64, treeID: ptr array[4,byte], sessionID: ptr array[8,byte]):bool =
    var smb2Header:SMB2Header = SMB2HeaderFiller(1,1,64,messageID[],treeID[],sessionID[])
    var ntlmSSPNegotiate:NTLMSSPNegotiate = NTLMSSPNegotiateFiller(negotiateFlags)
    var smb2SessionSetup:SessionSetupHeader = SessionSetupHeaderFiller(cast[uint16](sizeof(NTLMSSPNegotiate)))
    var netbiosHeader:NetBiosHeader = NetBiosFiller(sizeof(SMB2Header) + sizeof(NTLMSSPNegotiate) + sizeof(SessionSetupHeader))
    var dataLength:int = sizeof(SMB2Header) + sizeof(NTLMSSPNegotiate) + sizeof(SessionSetupHeader)+sizeof(NetBiosHeader)
    var sendData:seq[byte]=newSeq[byte](dataLength)
    var returnValue:array[5096,byte]
    var returnSize:uint32
    copyMem(addr sendData[0],addr netbiosHeader, sizeof(NetBiosHeader))
    copyMem(addr sendData[sizeof(NetBiosHeader)],addr smb2Header, sizeof(SMB2Header))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)],addr smb2SessionSetup, sizeof(SessionSetupHeader))
    copyMem(addr sendData[sizeof(SMB2Header)+sizeof(NetBiosHeader)+sizeof(SessionSetupHeader)],addr ntlmSSPNegotiate, sizeof(NTLMSSPNegotiate))
    (returnValue,returnSize) = SendAndReceiveFromSocket(socket,addr sendData)
    # Check NT Status value - STATUS_MORE_PROCESSING_REQUIRED
    if(returnValue[12] == 0x16 and returnValue[13] == 0x00 and returnValue[14] == 0x00 and returnValue[15] == 0xc0):
        messageID[] = messageID[]+1
        return true
    else:
        return false







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


proc SMB2HeaderFiller(packetCommand:uint16,messageID:uint64,treeID: array[4,byte],sessionID: array[8,byte]):SMB2Header =
    var returnStruct:SMB2Header
    returnStruct.ProtocolID = [ byte 0xfe, 0x53, 0x4d, 0x42 ]
    returnStruct.HeaderLength = 64
    returnStruct.CreditCharge = 1
    returnStruct.ChannelSequence = 0
    returnStruct.Reserved = 0
    returnStruct.Command = packetCommand
    returnStruct.CreditsRequested = 0
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


proc NegotiateSMB2*(socket: net.Socket,messageID:ptr uint64,treeID:ptr array[4,byte],sessionID:ptr array[8,byte]):bool=
    var smb2Header:SMB2Header = SMB2HeaderFiller(0,messageID[],treeID[],sessionID[])
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
    return true





import ptr_math
import Structs

proc NetBiosFiller*(packetLength:int): NetBiosHeader = 
    var tempPointer: ptr byte = cast[ptr byte](unsafeAddr packetLength)
    var lengthArray: array[3,byte] = [(tempPointer+2)[],(tempPointer+1)[],(tempPointer)[]]
    var returnStruct:NetbiosHeader
    returnStruct.MessageType = 0x00
    returnStruct.Length = lengthArray
    return returnStruct


proc SMB2HeaderFiller*(packetCommand:uint16,creditCharge:uint16,creditsRequested:uint16,messageID:uint64,treeID: array[4,byte],sessionID: array[8,byte]):SMB2Header =
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


proc SMB2NegotiateFiller*():SMB2NegotiateRequest = 
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

proc NTLMSSPNegotiateFiller*(negotiateFlags:seq[byte]):NTLMSSPNegotiate = 
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

proc SessionSetupHeaderFiller*(blobLength:uint16):SessionSetupHeader =
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

proc NTLMSSPAuthFiller*(ntlmSSPResponseLength:int):NTLMSSPAuth = 
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

proc TreeConnectRequestFiller*(smbPathLength:int):TreeConnectRequest = 
    var returnStruct:TreeConnectRequest
    var pathLength:uint32 = cast[uint32](smbPathLength) 
    var pathLengthBytes:array[2,byte] = [(cast[ptr byte](addr pathLength))[],(cast[ptr byte](addr(pathLength)) + 1)[] ]
    returnStruct.StructureSize = [byte 0x09,0x00]
    returnStruct.Reserved = [byte 0x00, 0x00]
    returnStruct.PathOffset = [byte 0x48, 0x00]
    returnStruct.PathLength = pathLengthBytes
    return returnStruct

proc CreateRequestFileFiller*(smbNamedPipeLength:int):CreateRequestFile = 
    var returnStruct:CreateRequestFile
    var pathLength:uint32 = cast[uint32](smbNamedPipeLength) 
    var pathLengthBytes:array[2,byte] = [(cast[ptr byte](addr pathLength))[],(cast[ptr byte](addr(pathLength)) + 1)[] ]
    returnStruct.StructureSize = [byte 0x39, 0x00]
    returnStruct.Flags = 0x00
    returnStruct.RequestedOplockLevel = 0x00
    returnStruct.Impersonation = [byte 0x02, 0x00, 0x00, 0x00]
    returnStruct.SMBCreateFlags = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.Reserved = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.DesiredAccess = [byte 0x00, 0x00, 0x00, 0xc0]
    returnStruct.FileAttributes = [byte 0x80, 0x00, 0x00, 0x00]
    returnStruct.ShareAccess = [byte 0x07, 0x00, 0x00, 0x00]
    returnStruct.CreateDisposition = [byte 0x01, 0x00, 0x00, 0x00]
    returnStruct.CreateOptions = [byte 0x40, 0x00, 0x00, 0x00]
    returnStruct.NameOffset = [byte 0x78,0x00]
    returnStruct.NameLength = pathLengthBytes
    returnStruct.CreateContextsOffset = [byte  0x00, 0x00, 0x00, 0x00]
    returnStruct.CreateContextsLength = [byte 0x00, 0x00, 0x00, 0x00]
    return returnStruct
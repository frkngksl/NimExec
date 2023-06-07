import ptr_math
import Structs
import AuxFunctions

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

proc RPCBindFiller*(callID:int,contextID:array[2,byte],interfaceUUID:array[16,byte],interfaceUUIDVersion:array[2,byte]):RPCBind = 
    var returnStruct:RPCBind
    returnStruct.Version = 0x05
    returnStruct.VersionMinor = 0x00
    returnStruct.PacketType = 0x0b
    returnStruct.PacketFlags = 0x03
    returnStruct.DataRepresentation = [byte 0x10, 0x00, 0x00, 0x00]
    returnStruct.FragLength = [byte 0x74, 0x00]
    returnStruct.AuthLength = [byte 0x00, 0x00]
    #returnStruct.CallID = callID
    returnStruct.CallID = [(cast[ptr byte](unsafeAddr callID))[],(cast[ptr byte](unsafeAddr(callID)) + 1)[],(cast[ptr byte](unsafeAddr(callID)) + 2)[],(cast[ptr byte](unsafeAddr(callID)) + 3)[] ]
    returnStruct.MaxXmitFrag = [byte 0xb8, 0x10]
    returnStruct.MaxRecvFrag = [byte 0xb8, 0x10]
    returnStruct.AssocGroup = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.NumCtxItems = 0x02
    returnStruct.Unknown = [byte 0x00, 0x00, 0x00]
    returnStruct.ContextID = contextID
    returnStruct.NumTransItems = 0x01
    returnStruct.Unknown2 = 0x00
    returnStruct.Interface = interfaceUUID
    returnStruct.InterfaceVer = interfaceUUIDVersion
    returnStruct.InterfaceVerMinor = [byte 0x00, 0x00]
    returnStruct.TransferSyntax = [byte 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]
    returnStruct.TransferSyntaxVer = [byte  0x02, 0x00, 0x00, 0x00]
    returnStruct.ContextID2 = [byte 0x01, 0x00]
    returnStruct.NumTransItems2 = 0x01
    returnStruct.Unknown3 = 0x00
    returnStruct.Interface2 = [byte 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]
    returnStruct.InterfaceVer2 = [byte 0x02, 0x00]
    returnStruct.InterfaceVerMinor2 = [byte 0x00, 0x00]
    returnStruct.TransferSyntax2 = [byte 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.TransferSyntaxVer2 = [byte 0x01, 0x00 ,0x00, 0x00]
    return returnStruct

proc SMB2WriteRequest*(packetWriteLength:int,fileID:ptr array[16,byte]):SMB2WriteHeader = 
    var returnStruct:SMB2WriteHeader
    returnStruct.StructureSize = [byte 0x31, 0x00]
    returnStruct.DataOffset = [byte 0x70, 0x00]
    returnStruct.Length = [(cast[ptr byte](unsafeAddr packetWriteLength))[],(cast[ptr byte](unsafeAddr(packetWriteLength)) + 1)[],(cast[ptr byte](unsafeAddr(packetWriteLength)) + 2)[],(cast[ptr byte](unsafeAddr(packetWriteLength)) + 3)[] ]
    returnStruct.Offset = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.FileID = fileID[]
    returnStruct.Channel = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.RemainingBytes = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.WriteChannelInfoOffset = [byte 0x00, 0x00]
    returnStruct.WriteChannelInfoLength = [byte 0x00, 0x00]
    returnStruct.Flags = [byte 0x00, 0x00, 0x00, 0x00]

    return returnStruct

proc SMB2IoctlRequest*(fileID:ptr array[16,byte],packetIoctlLength:int):SMB2IoctlHeader = 
    var returnStruct:SMB2IoctlHeader
    returnStruct.StructureSize = [byte 0x39, 0x00]
    returnStruct.Reserved = [byte 0x00, 0x00]
    returnStruct.Function = [byte 0x17, 0xc0, 0x11, 0x00]
    returnStruct.FileID = fileID[]
    returnStruct.BlobOffset = [byte 0x78, 0x00, 0x00, 0x00]
    returnStruct.BlobLength = [(cast[ptr byte](unsafeAddr packetIoctlLength))[],(cast[ptr byte](unsafeAddr(packetIoctlLength)) + 1)[],(cast[ptr byte](unsafeAddr(packetIoctlLength)) + 2)[],(cast[ptr byte](unsafeAddr(packetIoctlLength)) + 3)[] ]
    returnStruct.MaxInsize = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.BlobOffset2 = [byte 0x78, 0x00, 0x00, 0x00]
    returnStruct.BlobLength2 = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.MaxOutSize = [byte 0x00, 0x04, 0x00, 0x00]
    returnStruct.Flags = [byte 0x01, 0x00, 0x00, 0x00]
    returnStruct.Reserved2 = [byte 0x00, 0x00, 0x00, 0x00]

    return returnStruct

proc SMB2ReadRequest*(fileID: array[16,byte], length: array[4, byte] =  [byte 0xb8, 0x0c, 0x00, 0x00 ]):SMB2ReadHeader = 
    var returnStruct:SMB2ReadHeader
    returnStruct.StructureSize = [byte 0x31, 0x00]
    returnStruct.Padding = 0x50
    returnStruct.Flags = 0x00
    returnStruct.Length = length
    returnStruct.Offset = [byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    returnStruct.FileID = fileID
    returnStruct.MinimumCount = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.Channel = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.RemainingBytes = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.ReadChannelInfoLength = [byte 0x00, 0x00]
    returnStruct.ReadChannelInfoOffset = [byte 0x00, 0x00]
    returnStruct.Buffer = 0x30
    return returnStruct

proc RPCHeaderFiller*(packetLength:int, callID: ptr int, opNum: array[2,byte]):RPCHeader = 
    var returnStruct:RPCHeader
    var writeLength:uint16 = cast[uint16](packetLength + 24)
    var callIdTemp:uint32 = cast[uint32](callID[])
    returnStruct.Version = 0x05
    returnStruct.VersionMinor = 0x00
    returnStruct.PacketType = 0x00
    returnStruct.PacketFlags = 0x03
    returnStruct.DataRepresentation = [byte 0x10, 0x00, 0x00, 0x00]
    returnStruct.FragLength = [(cast[ptr byte](addr writeLength))[],(cast[ptr byte](addr(writeLength)) + 1)[]]
    returnStruct.AuthLength = [byte 0x00, 0x00]
    returnStruct.CallID = [(cast[ptr byte](addr callIdTemp))[],(cast[ptr byte](addr(callIdTemp)) + 1)[],(cast[ptr byte](addr(callIdTemp)) + 2)[],(cast[ptr byte](addr(callIdTemp)) + 3)[] ]
    returnStruct.AllocHint = [byte 0x00, 0x00, 0x00, 0x00]
    returnStruct.ContextID = [byte 0x00, 0x00]
    returnStruct.OpNum = opNum
    return returnStruct

proc OpenSCManagerWFiller*(targetBytesInWCharForm:WideCStringObj):seq[byte] = 
    var remainingData:OpenSCManagerWData
    var marshalledTarget:seq[byte] = MarshallStringForRPC(targetBytesInWCharForm,true)
    var returnData:seq[byte] = newSeq[byte](marshalledTarget.len + sizeof(OpenSCManagerWData))
    remainingData.Database = [byte  0x00, 0x00, 0x00, 0x00]
    remainingData.AccessMask = [byte 0x3F, 0x00, 0x0F, 0x00]
    copyMem(addr returnData[0],addr marshalledTarget[0],marshalledTarget.len)
    copyMem(addr returnData[marshalledTarget.len],addr remainingData, sizeof(remainingData))
    return returnData

proc EnumServicesStatusWFiller*(scManagerHandle: ptr array[20,byte], bufferSize: uint32):EnumServicesStatusWData = 
    var returnStruct:EnumServicesStatusWData
    var bufferArray:array[4,byte] = [(cast[ptr byte](unsafeAddr bufferSize))[],(cast[ptr byte](unsafeAddr(bufferSize)) + 1)[],(cast[ptr byte](unsafeAddr(bufferSize)) + 2)[],(cast[ptr byte](unsafeAddr(bufferSize)) + 3)[] ]
    returnStruct.ContextHandle = scManagerHandle[]
    returnStruct.ServiceType = [byte 0x10, 0x00, 0x00, 0x00]
    returnStruct.ServiceState = [byte 0x03, 0x00, 0x00, 0x00]
    returnStruct.BufferSize = bufferArray
    returnStruct.ResumeIndex = [byte 0x00, 0x00, 0x00, 0x00]
    return returnStruct


type
    OPTIONS* {.bycopy,packed.} = object
        IsVerbose*: bool
        Username*: string
        Hash*: string
        Domain*: string
        Target*: string
        Command*: string
        Service*:string
        OutputUsername*:string

    NetBiosHeader* {.bycopy,packed.} = object
        MessageType*: byte
        Length*: array[3,byte]

    SMB2Header* {.bycopy,packed.} = object
        ProtocolID*: array[4,byte]
        HeaderLength*: uint16
        CreditCharge*: uint16
        ChannelSequence*: uint16
        Reserved*: uint16
        Command*: uint16
        CreditsRequested*: uint16
        Flags*: uint32
        ChainOffset*: uint32
        MessageID*: uint64
        ProcessID*: uint32
        TreeID*: array[4,byte]
        SessionID*: array[8,byte]
        Signature*: array[16,byte]

    SMB2NegotiateRequest* {.bycopy,packed.} = object
        StructureSize*: uint16
        DialectCount*: uint16
        SecurityMode*: uint16
        Reserved1*: uint16
        Capabilities*: array[4,byte]
        ClientGUID*: array[16,byte]
        NegotiateContextOffset*: uint32
        NegotiateContextCount*: uint16
        Reserved2*: uint16
        Dialect1*: array[2,byte]
        Dialect2*: array[2,byte]

    SessionSetupHeader* {.bycopy,packed.} = object
        StructureSize*: uint16
        Flags*:byte
        SecurityMode*:byte
        Capabilities*: array[4,byte]
        Channel*: array[4,byte]
        BlobOffset*: uint16
        BlobLength*: uint16
        PreviousSessionId*: array[8,byte]
    
    NTLMSSPNegotiate* {.bycopy,packed.} = object
        InitialContextTokenID*:byte
        InitialContextTokenLength*:byte
        ThisMechID*:byte
        ThisMechLength*:byte
        OID*:array[6,byte]
        InnerContextTokenID*:byte
        InnerContextTokenLength*:byte
        InnerContextTokenID2*:byte
        InnerContextTokenLength2*:byte
        MechTypesID*:byte
        MechTypesLength*:byte
        MechTypesID2*:byte
        MechTypesLength2*:byte
        MechTypesID3*:byte
        MechTypesLength3*:byte
        MechType*:array[10,byte]
        MechTokenID*:byte
        MechTokenLength*:byte
        NTLMSSPID*:byte
        NTLMSSPLength*:byte
        Identifier*:array[8,byte]
        MessageType*:array[4,byte]
        NegotiateFlags*:array[4,byte]
        CallingWorkstationDomain*:array[8,byte]
        CallingWorkstationName*:array[8,byte]

    NTLMSSPAuth* {.bycopy,packed.} = object
        NTLMSSPAuthASNID*:array[2,byte]
        NTLMSSPAuthASNLength*:array[2,byte]
        NTLMSSPAuthASNID2*:array[2,byte]
        NTLMSSPAuthASNLength2*:array[2,byte]
        NTLMSSPAuthASNID3*:array[2,byte]
        NTLMSSPAuthASNLength3*:array[2,byte]
        NTLMSSPAuthNTLMSSPID*:array[2,byte]
        NTLMSSPAuthNTLMSSPLength*:array[2,byte]
    
    TreeConnectRequest* {.bycopy,packed.} = object
        StructureSize*:array[2,byte]
        Reserved*:array[2,byte]
        PathOffset*:array[2,byte]
        PathLength*:array[2,byte]

    CreateRequestFile* {.bycopy,packed.} = object
        StructureSize*:array[2,byte]
        Flags*:byte
        RequestedOplockLevel*:byte
        Impersonation*:array[4,byte]
        SMBCreateFlags*:array[8,byte]
        Reserved*:array[8,byte]
        DesiredAccess*:array[4,byte]
        FileAttributes*:array[4,byte]
        ShareAccess*:array[4,byte]
        CreateDisposition*:array[4,byte]
        CreateOptions*:array[4,byte]
        NameOffset*:array[2,byte]
        NameLength*:array[2,byte]
        CreateContextsOffset*:array[4,byte]
        CreateContextsLength*:array[4,byte]




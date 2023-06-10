const 
    SERVICE_DRIVER* = 0x0000000B
    SERVICE_FILE_SYSTEM_DRIVER* = 0x00000002
    SERVICE_KERNEL_DRIVER* = 0x00000001
    SERVICE_WIN32* = 0x00000030
    SERVICE_WIN32_OWN_PROCESS* = 0x00000010
    SERVICE_WIN32_SHARE_PROCESS* = 0x00000020

    SERVICE_CONTINUE_PENDING* = 0x00000005
    SERVICE_PAUSE_PENDING* = 0x00000006
    SERVICE_PAUSED* = 0x00000007
    SERVICE_RUNNING* = 0x00000004
    SERVICE_START_PENDING* = 0x00000002
    SERVICE_STOP_PENDING* = 0x00000003
    SERVICE_STOPPED* = 0x00000001

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
    
    ServiceInfo* {.bycopy,packed.} = object
        ServiceType*:uint32
        ServiceState*:uint32
        ServiceName*:string
        DisplayName*:string

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

    RPCBind* {.bycopy,packed.} = object
        Version*:byte
        VersionMinor*:byte
        PacketType*:byte
        PacketFlags*:byte
        DataRepresentation*:array[4,byte]
        FragLength*:array[2,byte]
        AuthLength*:array[2,byte]
        CallID*:array[4,byte]
        MaxXmitFrag*:array[2,byte]
        MaxRecvFrag*:array[2,byte]
        AssocGroup*:array[4,byte]
        NumCtxItems*:byte
        Unknown*:array[3,byte]
        ContextID*:array[2,byte]
        NumTransItems*:byte
        Unknown2*:byte
        Interface*:array[16,byte]
        InterfaceVer*:array[2,byte]
        InterfaceVerMinor*:array[2,byte]
        TransferSyntax*:array[16,byte]
        TransferSyntaxVer*:array[4,byte]
        ContextID2*:array[2,byte]
        NumTransItems2*:byte
        Unknown3*:byte
        Interface2*:array[16,byte]
        InterfaceVer2*:array[2,byte]
        InterfaceVerMinor2*:array[2,byte]
        TransferSyntax2*:array[16,byte]
        TransferSyntaxVer2*:array[4,byte]

    SMB2WriteHeader* {.bycopy,packed.} = object
        StructureSize*: array[2,byte]
        DataOffset*: array[2,byte]
        Length*:array[4,byte]
        Offset*: array[8,byte]
        FileID*: array[16,byte]
        Channel*: array[4,byte]
        RemainingBytes*: array[4,byte]
        WriteChannelInfoOffset*: array[2,byte]
        WriteChannelInfoLength*: array[2,byte]
        Flags*: array[4,byte]

    
    SMB2IoctlHeader* {.bycopy,packed.} = object
        StructureSize*: array[2,byte]
        Reserved*: array[2,byte]
        Function*: array[4,byte]
        FileID*: array[16,byte]
        BlobOffset*: array[4, byte]
        BlobLength*: array[4, byte]
        MaxInsize*: array[4, byte]
        BlobOffset2*: array[4, byte]
        BlobLength2*: array[4, byte]
        MaxOutSize*: array[4, byte]
        Flags*: array[4, byte]
        Reserved2*: array[4, byte]
    
    SMB2ReadHeader* {.bycopy,packed.} = object
        StructureSize*: array[2,byte]
        Padding*: byte
        Flags*: byte
        Length*: array[4,byte]
        Offset*: array[8, byte]
        FileID*: array[16, byte]
        MinimumCount*: array[4, byte]
        Channel*: array[4, byte]
        RemainingBytes*: array[4, byte]
        ReadChannelInfoOffset*: array[2, byte]
        ReadChannelInfoLength*: array[2, byte]
        Buffer*: byte
        
    RPCHeader* {.bycopy,packed.} = object
        Version*: byte
        VersionMinor*: byte
        PacketType*: byte
        PacketFlags*: byte
        DataRepresentation*: array[4,byte]
        FragLength*: array[2,byte]
        AuthLength*: array[2,byte]
        CallID*: array[4,byte]
        AllocHint*: array[4, byte]
        ContextID*: array[2,byte]
        OpNum*: array[2,byte]
    
    OpenSCManagerWData* {.bycopy,packed.} = object
        Database*: array[4, byte]
        AccessMask*: array[4, byte]
    
    EnumServicesStatusWData* {.bycopy,packed.} = object
        ContextHandle*: array[20,byte]
        ServiceType*: array[4,byte]
        ServiceState*: array[4,byte]
        BufferSize*: array[4,byte]
        ResumeIndex*: array[4,byte]






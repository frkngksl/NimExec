type
    OPTIONS* {.bycopy,packed.} = object
        IsVerbose*: bool
        Username*: string
        Hash*: string
        Domain*: string
        Target*: string
        Command*: string
        Service*:string

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


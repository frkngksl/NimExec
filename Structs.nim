type
    OPTIONS* {.bycopy,packed.} = object
        IsVerbose*: bool
        Username*: string
        Hash*: string
        Domain*: string
        Target*: string
        Service*:string
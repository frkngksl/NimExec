import Structs
proc PrintBanner*():void = 
    var banner = """
 
                                                                                             _..._     
                                                                                          .-'_..._''.  
   _..._   .--. __  __   ___         __.....__                          __.....__       .' .'      '.\ 
 .'     '. |__||  |/  `.'   `.   .-''         '.                    .-''         '.    / .'            
.   .-.   ..--.|   .-.  .-.   ' /     .-''"'-.  `.                 /     .-''"'-.  `. . '              
|  '   '  ||  ||  |  |  |  |  |/     /________\   \ ____     _____/     /________\   \| |              
|  |   |  ||  ||  |  |  |  |  ||                  |`.   \  .'    /|                  || |              
|  |   |  ||  ||  |  |  |  |  |\    .-------------'  `.  `'    .' \    .-------------'. '              
|  |   |  ||  ||  |  |  |  |  | \    '-.____...---.    '.    .'    \    '-.____...---. \ '.          . 
|  |   |  ||__||__|  |__|  |__|  `.             .'     .'     `.    `.             .'   '. `._____.-'/ 
|  |   |  |                        `''-...... -'     .'  .'`.   `.    `''-...... -'       `-.______ /  
|  |   |  |                                        .'   /    `.   `.                               `   
'--'   '--'                                       '----'       '----'                                  

                @R0h1rr1m          

"""
    echo banner


proc PrintHelp*():void =
    var optionsString = """

    -h | --help                             Show the help message.
    -v | --verbose                          Enable a more verbose output.
    -u | --username <Username>              Username for NTLM Authentication.* 
    -h | --hash <NTLM Hash>                 NTLM passwword hash for NTLM Authentication.*
    -d | --domain <Domain>                  Domain name for NTLM Authentication.*
    -t | --target <Target>                  Lateral movement target.*
    -s | --service <Service Name>           Name of the service instead of a random one.
    """
    echo(optionsString)


proc ParseArgs*(argc:int, argv:seq[string], optionsStruct:ptr OPTIONS):bool =
    optionsStruct.Service = ""
    optionsStruct.Username = ""
    optionsStruct.Hash = ""
    optionsStruct.Domain = ""
    optionsStruct.Target = ""
    optionsStruct.IsVerbose = false
    var i:int = 0
    while(i<argc):
        if(argv[i] == "-v" or argv[i] == "--verbose"):
            optionsStruct.IsVerbose = true
        elif(argv[i] == "-h" or argv[i] == "--help"):
            PrintHelp()
            quit(0)
        elif(argv[i] == "-u" or argv[i] == "--username"):
            i+=1
            if(i>argc):
                return false
            optionsStruct.Username = argv[i]
        elif(argv[i] == "-h" or argv[i] == "--hash"):
            i+=1
            if(i>argc):
                return false
            optionsStruct.Hash = argv[i]
        elif(argv[i] == "-d" or argv[i] == "--domain"):
            i+=1
            if(i>argc):
                return false
            optionsStruct.Domain = argv[i]
        elif(argv[i] == "-t" or argv[i] == "--target"):
            i+=1
            if(i>argc):
                return false
            optionsStruct.Target = argv[i]
        elif(argv[i] == "-s" or argv[i] == "--service"):
            i+=1
            if(i>argc):
                return false
            optionsStruct.Service = argv[i]
        elif(i != 0):
            echo "[!] Unknown argument!"
            return false
        i+=1
    if(optionsStruct.Username == "" or optionsStruct.Hash == "" or optionsStruct.Domain == "" or optionsStruct.Target == ""):
        echo "[!] Missing one or more arguments!"
        return false
    return true
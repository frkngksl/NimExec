import std/os
import OptionsHelper
import Structs


when isMainModule:
    PrintBanner()
    var optionsStruct:OPTIONS
    if(not ParseArgs(paramCount(),commandLineParams(),addr(optionsStruct))):
        PrintHelp() 
        quit(0)


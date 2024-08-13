import "pe"

       
rule Skriptgg_detect {
    meta:
        description = "Detecta contenido relacionado con Skript.gg"
        author = "TuNombre"
        name = "Skript Cheat"
        date = "2024-08-12"
        
    strings:
        $s1 = "skript" fullword ascii /* score: '23.00'*/
        $s2 = "OKERNEL32.dll" fullword ascii /* score: '23.00'*/       
        $s3 = ".key" fullword ascii /* score: '15.00'*/
        $s4 = "boostrap" fullword ascii /* score: '26.00'*/
        $s5 = "skript.gg" fullword ascii /* score: '39.00'*/
        $s6 = "104.26.0.61" fullword ascii /* score: '45.00'*/
        $s7 = "www.skript.gg" fullword ascii /* score: '50.00'*/
        $s8 = "license.dat" fullword ascii /* score: '50.00'*/ 
        $s9 = "README.txt" fullword ascii /* score: '60.00'*/     
        $s10 = "https://skript.gg" ascii /* score: '45.00'*/
        $s11 = "https://skript.gg" fullword ascii /* score: '60.00'*/     
        $s12 = "skript.dll" fullword ascii /* score: '27.00'*/       
        $s13 = "loader.dll" fullword ascii /* score: '27.00'*/ 
        $s14 = "No Collision Key" fullword ascii /* score: '25.00'*/
        $s15 = "Secondary Boost Key" fullword ascii /* score: '25.00'*/
        $s16 = "nvldumdx.dll" fullword ascii /* score: '23.00'*/
        $s17 = "Error reading SteamExe key" fullword ascii /* score: '25.00'*/
        $s18 = "Error writing description" fullword ascii /* score: '23.00'*/
        $s19 = "gm.dll" fullword ascii /* score: '20.00'*/ 
        $s20 = "Enter key" fullword ascii /* score: '25.00'*/         
        $s21 = "2023/02/10:05:18:04!" fullword ascii /* score: '50.00'*/ 
        $s22 = "SKRIPT" fullword ascii /* score: '50.00'*/      
    condition:
        pe.imphash() == "ed089b32dc5a5d25e18d82e2e09fd291" or
        uint16(0) == 0x754e and filesize < 19000KB and
        4 of them
}

rule GoshStrings {
    meta:
        description = "Detecta cadenas específicas relacionadas con Gosh"
        author = "TuNombre"
        name = "Gosth Cheat"
        date = "2024-08-12"
        
    strings:
        $s1 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
        $s2 = "OKERNEL32.dll" fullword ascii /* score: '23.00'*/
        $s3 = "ylogsu" fullword ascii /* score: '10.00'*/
        $s4 = "=exeCd" fullword ascii /* score: '9.00'*/
        $s5 = "eyeh\"DoA7p" fullword ascii /* score: '9.00'*/
        $s6 = "* ;2BQB" fullword ascii /* score: '9.00'*/
        $s7 = "* #9SF" fullword ascii /* score: '9.00'*/
        $s8 = "jnnkour" fullword ascii /* score: '8.00'*/
        $s9 = "Pftplw" fullword ascii /* score: '8.00'*/
        $s10 = "__CxxFrameHandler4" fullword ascii /* score: '7.00'*/
        $s11 = "pjT.aJK" fullword ascii /* score: '7.00'*/
        $s12 = "K[H:\\J" fullword ascii /* score: '7.00'*/
        $s13 = "HG:\\yjP" fullword ascii /* score: '7.00'*/
        $s14 = "gYd:\"w" fullword ascii /* score: '7.00'*/
        $s15 = "4Wv.gYZ" fullword ascii /* score: '7.00'*/
        $s16 = "AI:\\K3" fullword ascii /* score: '7.00'*/
        $s17 = "+~bFFQ?.bFF" fullword ascii /* score: '7.00'*/
        $s18 = "Y1kn:\"" fullword ascii /* score: '7.00'*/
        $s19 = "t!sR:\"" fullword ascii /* score: '7.00'*/
        $s20 = "xB[@aR:\"!" fullword ascii /* score: '7.00'*/
    condition:
        pe.imphash() == "ed089b32dc5a5d25e18d82e2e09fd291" or
        uint16(0) == 0x754e and filesize < 20000KB and
        8 of them
}

rule cleaners {
    meta:
        description = "Detecta cadenas específicas relacionadas con Gosh"
        author = "TuNombre"
        name = "Generic Cleaner"
        date = "2024-08-12"
    strings:
        $ccleaner_signature = "CCleaner64.exe"
        $privazer_signature = "PrivaZer.exe"
    condition:
        any of ($ccleaner_signature, $privazer_signature)
}


rule EscapeService {
    meta:
        description = "Detecta cadenas específicas relacionadas con Gosh"
        author = "TuNombre"
        name = "Generic Cheat (a)"
        date = "2024-08-12"
    strings:
        $x1 = "DMEnvironment BaseDllReadWriteIniFile BaseDumpAppcompatCache BaseDumpAppcompatCacheWorker BaseElevationPostProcessing BaseFlushA" ascii
        $x2 = "DMEnvironment BaseDllReadWriteIniFile BaseDumpAppcompatCache BaseDumpAppcompatCacheWorker BaseElevationPostProcessing BaseFlushA" ascii
        $x3 = "C:\\Users\\Rafa0Reis\\Desktop\\Cheats\\External\\Driver\\x64\\Release\\Driver.pdb" fullword ascii
        $x4 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\objfre_wnet_AMD64\\amd64\\iqvw64e.pdb" fullword ascii
        $x5 = "acheSize SetSystemPowerState SetSystemTime SetSystemTimeAdjustment SetTapeParameters SetTapePosition SetTermsrvAppInstallMode Se" ascii
        $x6 = "tion TpCancelAsyncIoOperation TpCaptureCaller TpCheckTerminateWorker TpDbgDumpHeapUsage TpDbgSetLogRoutine TpDisablePoolCallback" ascii
        $x7 = "gleObject WaitForSingleObjectEx WaitNamedPipeA WaitNamedPipeW WerGetFlags WerGetFlagsWorker WerRegisterAdditionalProcess WerRegi" ascii
        $x8 = "aceA OpenPrivateNamespaceW OpenProcess OpenProfileUserMapping OpenSemaphoreA OpenSemaphoreW OpenThread OpenWaitableTimerA OpenWa" ascii
        $x9 = "es RtlpConvertRelativeToAbsoluteSecurityAttribute RtlpCreateProcessRegistryInfo RtlpEnsureBufferSize RtlpExecuteUmsThread RtlpFr" ascii
        $x10 = "[-] Failed to get ntoskrnl.exe" fullword ascii
        $s11 = "nipulationInputTarget MITStopAndEndInertia MITSynthesizeMouseInput MITSynthesizeMouseWheel MITSynthesizeTouchInput MITUpdateInpu" ascii
        $s12 = "anguagesA EnumUILanguagesW EnumerateLocalComputerNamesA EnumerateLocalComputerNamesW EraseTape EscapeCommFunction ExecuteUmsThre" ascii
        $s13 = "r DrawMenuBarTemp DrawStateA DrawStateW DrawTextA DrawTextExA DrawTextExW DrawTextW DwmGetDxRgn DwmGetDxSharedSurface DwmGetRemo" ascii
        $s14 = "c LdrInitializeEnclave LdrInitializeThunk LdrLoadAlternateResourceModule LdrLoadAlternateResourceModuleEx LdrLoadDll LdrLoadEncl" ascii
        $s15 = "ansactionManager ZwCreateUserProcess ZwCreateWaitCompletionPacket ZwCreateWaitablePort ZwCreateWnfStateName ZwCreateWorkerFactor" ascii
        $s16 = "etNLSVersionEx GetNamedPipeAttribute GetNamedPipeClientComputerNameA GetNamedPipeClientComputerNameW GetNamedPipeClientProcessId" ascii
        $s17 = "ToStringW RtlEthernetStringToAddressA RtlEthernetStringToAddressW RtlExecuteUmsThread RtlExitUserProcess RtlExitUserThread RtlEx" ascii
        $s18 = "GetNamedPipeClientSessionId GetNamedPipeHandleStateA GetNamedPipeHandleStateW GetNamedPipeServerProcessId GetNamedPipeServerSess" ascii
        $s19 = "C:\\Users\\Daniel\\Documents\\Projects\\Pessoal\\Captures\\x64\\Release\\Fivem-External.pdb" fullword ascii
        $s20 = "obSet ZwCreateKey ZwCreateKeyTransacted ZwCreateKeyedEvent ZwCreateLowBoxToken ZwCreateMailslotFile ZwCreateMutant ZwCreateNamed" ascii
    condition:
        1 of ($x*) and 7 of them
}
import "pe"

rule Skriptgg_detect {
    meta:
        name = "Skript Cheat"
    strings:
        $s1 = "skript" fullword ascii
        $s2 = "OKERNEL32.dll" fullword ascii       
        $s3 = ".key" fullword ascii
        $s4 = "boostrap" fullword ascii
        $s5 = "skript.gg" fullword ascii
        $s6 = "104.26.0.61" fullword ascii
        $s7 = "www.skript.gg" fullword ascii
        $s8 = "license.dat" fullword ascii
        $s9 = "README.txt" fullword ascii
        $s10 = "https://skript.gg" ascii
        $s11 = "https://skript.gg" fullword ascii
        $s12 = "skript.dll" fullword ascii       
        $s13 = "loader.dll" fullword ascii
        $s14 = "No Collision Key" fullword ascii
        $s15 = "Secondary Boost Key" fullword ascii
        $s16 = "nvldumdx.dll" fullword ascii
        $s17 = "Error reading SteamExe key" fullword ascii
        $s18 = "Error writing description" fullword ascii
        $s19 = "gm.dll" fullword ascii
        $s20 = "Enter key" fullword ascii
        $s21 = "2023/02/10:05:18:04!" fullword ascii
        $s22 = "SKRIPT" fullword ascii
    condition:
        pe.imphash() == "ed089b32dc5a5d25e18d82e2e09fd291" or
        uint16(0) == 0x754e and filesize < 19000KB and
        4 of them
}

rule GoshStrings_v1 {
    meta:
        name = "Gosth Cheat"
    strings:
        $s1 = "VCRUNTIME140_1.dll" fullword ascii
        $s2 = "OKERNEL32.dll" fullword ascii
        $s3 = "ylogsu" fullword ascii
        $s4 = "=exeCd" fullword ascii
        $s5 = "eyeh\"DoA7p" fullword ascii
        $s6 = "* ;2BQB" fullword ascii
        $s7 = "* #9SF" fullword ascii
        $s8 = "jnnkour" fullword ascii
        $s9 = "Pftplw" fullword ascii
        $s10 = "__CxxFrameHandler4" fullword ascii
        $s11 = "pjT.aJK" fullword ascii
        $s12 = "K[H:\\J" fullword ascii
        $s13 = "HG:\\yjP" fullword ascii
        $s14 = "gYd:\"w" fullword ascii
        $s15 = "4Wv.gYZ" fullword ascii
        $s16 = "AI:\\K3" fullword ascii
        $s17 = "+~bFFQ?.bFF" fullword ascii
        $s18 = "Y1kn:\"" fullword ascii
        $s19 = "t!sR:\"" fullword ascii
        $s20 = "xB[@aR:\"!" fullword ascii
    condition:
        pe.imphash() == "ed089b32dc5a5d25e18d82e2e09fd291" or
        uint16(0) == 0x754e and filesize < 20000KB and
        8 of them
}

rule GenericCleaner {
    meta:
        name = "Generic Cleaner"
    strings:
        $ccleaner_signature = "CCleaner64.exe"
        $privazer_signature = "PrivaZer.exe"
    condition:
        any of ($ccleaner_signature, $privazer_signature)
}

rule GenericCheat_a {
    meta:
        name = "Generic Cheat (a)"
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

rule SaturnBypass_v1 {
    meta:
        name = "Saturn Bypass"
    strings:
        $x1 = "!$512bdc60293a60db7ed2eac1ca48f0b5"
        $x2 = "!$4e30516ead18d69fa829b709ec82c632"
        $x3 = "!$ed5bc645366a2d70c419543279e82c69"
        $x4 = "!$9df236927275373cfa0b7f31c2bdbf00"
        $x5 = "!$d140ec7579dc36e3aaac33e85624b006"
    condition:
        1 of ($x*) and 4 of them
}

rule SkriptDLLStrings {
   meta: 
   name = "Skript.gg"
   strings:
      $x1 = "wldp.dll" fullword ascii
      $s2 = "skript.dll" fullword ascii
      $s3 = "nvldumdx.dll" fullword ascii
      $s4 = "nvldumd.dll" fullword ascii
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s7 = "OpenProcessToken" fullword ascii
      $s8 = "CreateProcessA" fullword ascii
      $s9 = "CreateRemoteThread" fullword ascii
      $s10 = "LoadLibraryA" fullword ascii
      $s11 = "OpenProcess" fullword ascii
      $s12 = "WriteProcessMemory" fullword ascii
      $s13 = "VirtualAllocEx" fullword ascii
      $s14 = "VirtualFreeEx" fullword ascii
      $s15 = "SetWindowsHookExA" fullword ascii
      $s16 = "SetWindowsHookExW" fullword ascii
      $s17 = "GetModuleHandleA" fullword ascii
      $s18 = "GetModuleHandleW" fullword ascii
   condition:
      4 of them
}

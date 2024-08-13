import "pe"

rule Skriptgg_detect {
    meta:
        name = "Skript Cheat"
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
        name = "Gosth Cheat"
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
        name = "Generic Cleaner"
    strings:
        $ccleaner_signature = "CCleaner64.exe"
        $privazer_signature = "PrivaZer.exe"
    condition:
        any of ($ccleaner_signature, $privazer_signature)
}

rule EscapeService {
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

rule SaturnBypassUnique {
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


rule skriptdllStrings {
   meta: 
   name = "Skript.gg"
   strings:
      $x1 = "wldp.dll" fullword ascii /* reversed goodware string 'lld.pdlw' */ /* score: '33.00'*/
      $s2 = "skript.dll" fullword ascii /* score: '23.00'*/
      $s3 = "nvldumdx.dll" fullword ascii /* score: '23.00'*/
      $s4 = "nvldumd.dll" fullword ascii /* score: '23.00'*/
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '21.00'*/
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s7 = "curity><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel" ascii /* score: '19.00'*/
      $s8 = "gm.dll" fullword ascii /* score: '17.00'*/
      $s9 = "+es84ow9Z5tHlWB9TH8GohJhXkCBkPoFY4kJAlxrNUAFTPs1bNAa3frZwoUSZtUPRmBnbcizP2FHWQegAo/ViPFF7EhCjTGy7nMB8eyBSCo1r7qZgkc9gdvXsoit7plT" ascii /* score: '16.00'*/
      $s10 = "\\mfpmp.exe" fullword ascii /* score: '16.00'*/
      $s11 = "Module %s download complete." fullword ascii /* score: '16.00'*/
      $s12 = "questedPrivileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmln" ascii /* score: '16.00'*/
      $s13 = "+es84ow9Z5tHlWB9TH8GohJhXkCBkPoFY4kJAlxrNUAFTPs1bNAa3frZwoUSZtUPRmBnbcizP2FHWQegAo/ViPFF7EhCjTGy7nMB8eyBSCo1r7qZgkc9gdvXsoit7plT" ascii /* score: '16.00'*/
      $s14 = "api-ms-win-core-processthreads-l1-1-2" fullword ascii /* score: '15.00'*/
      $s15 = "Error writing command" fullword ascii /* score: '15.00'*/
      $s16 = "/dumpsta" fullword ascii /* score: '14.00'*/
      $s17 = "\\\\?\\pipe\\discord-ipc-0" fullword ascii /* score: '14.00'*/
      $s18 = "kernelbase" fullword ascii /* score: '13.00'*/
      $s19 = "Error reading SteamExe key" fullword ascii /* score: '13.00'*/
      $s20 = "Error writing description" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x754e and filesize < 19000KB and
      1 of ($x*) and 6 of them
}

rule FiveMDetections_skript {
   meta:
   name = "Skript Cheat"
   strings:
      $x1 = "C:\\Users\\dev\\Desktop\\projects\\Skript\\sk_launcher\\x64\\Release\\sk_launcher.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><t" ascii /* score: '24.00'*/
      $s4 = " uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-mi" ascii /* score: '22.00'*/
      $s5 = "fo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrat" ascii /* score: '22.00'*/
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s7 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s8 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s9 = "object key" fullword ascii /* score: '9.00'*/
      $s10 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s11 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s12 = "syntax error " fullword ascii /* score: '9.00'*/
      $s13 = ".data$rs" fullword ascii /* score: '8.00'*/
      $s14 = ".?AVtype_error@detail@nlohmann@@" fullword ascii /* score: '7.00'*/
      $s15 = "pportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"></supportedOS><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"" ascii /* score: '7.00'*/
      $s16 = "type_error" fullword ascii /* score: '7.00'*/
      $s17 = ".?AVother_error@detail@nlohmann@@" fullword ascii /* score: '7.00'*/
      $s18 = "invalid comment; expecting '/' or '*' after '/'" fullword ascii /* score: '7.00'*/
      $s19 = "other_error" fullword ascii /* score: '7.00'*/
      $s20 = ".?AVparse_error@detail@nlohmann@@" fullword ascii /* score: '7.00'*/
   condition:
      pe.imphash() == "aa8025e0ff674e112eaafe12a2b8f849" or
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}


rule RedEngineStrings {
   meta:
   name = "RedEngine Loader"
   strings:
      $s1 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s2 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s3 = "xeUaj.BeM" fullword ascii /* score: '10.00'*/
      $s4 = "keWy:\"" fullword ascii /* score: '10.00'*/
      $s5 = "bngtL:\"ph" fullword ascii /* score: '10.00'*/
      $s6 = "* pa[h" fullword ascii /* score: '9.00'*/
      $s7 = "/getw:ls;a:u" fullword ascii /* score: '9.00'*/
      $s8 = "- -#LtO\"" fullword ascii /* score: '9.00'*/
      $s9 = "0XlircDt-yd" fullword ascii /* score: '9.00'*/
      $s10 = ".EBm+ " fullword ascii /* score: '8.00'*/
      $s11 = "%zqrl!." fullword ascii /* score: '8.00'*/
      $s12 = "rodigyo" fullword ascii /* score: '8.00'*/
      $s13 = "Section(2)['.data']" fullword ascii /* score: '8.00'*/
      $s14 = "gchegkf" fullword ascii /* score: '8.00'*/
      $s15 = "fdxpxfy" fullword ascii /* score: '8.00'*/
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s17 = "mRF:\\A~" fullword ascii /* score: '7.00'*/
      $s18 = "ic:\\mirn" fullword ascii /* score: '7.00'*/
      $s19 = "\"(Y:\"*Y<\"$Y>\"&Y@\" Y2\"\"Y4\"" fullword ascii /* score: '7.00'*/
      $s20 = "yAd.QYY" fullword ascii /* score: '7.00'*/
   condition:
   	  pe.imphash() == "007cb966e6a1a9392fbed8a94c6b324a" or
      uint16(0) == 0x754e and filesize < 19000KB and
      8 of them
}


rule TZInstaller {
   meta: 
   name = "TZ Installer"
   strings:
      $s1 = "https://scripts.sil.org/OFLPoppins-Light4.004ITFO; Poppins Light; 4.004b8RegularPoppins LightCopyright 2020 The Poppins Project " ascii /* score: '26.00'*/
      $s2 = "schannel: Failed to import cert file %s, password is bad" fullword ascii /* score: '23.50'*/
      $s3 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii /* score: '23.00'*/
      $s4 = "KeyMap[n] == -1 && \"Backend needs to either only use io.AddKeyEvent(), either only fill legacy io.KeysDown[] + io.KeyMap[]. Not" ascii /* score: '23.00'*/
      $s5 = "(BackendUsingLegacyKeyArrays == -1 || BackendUsingLegacyKeyArrays == 0) && \"Backend needs to either only use io.AddKeyEvent(), " ascii /* score: '23.00'*/
      $s6 = "KeyMap[n] == -1 && \"Backend needs to either only use io.AddKeyEvent(), either only fill legacy io.KeysDown[] + io.KeyMap[]. Not" ascii /* score: '23.00'*/
      $s7 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s8 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii /* score: '21.50'*/
      $s9 = "https://fontawesome.com" fullword ascii /* score: '21.00'*/
      $s10 = "Authors (https://github.com/itfoundry/Poppins)" fullword ascii /* score: '20.00'*/
      $s11 = "xinput1_1.dll" fullword ascii /* score: '20.00'*/
      $s12 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s13 = "xinput1_2.dll" fullword ascii /* score: '20.00'*/
      $s14 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii /* score: '19.00'*/
      $s15 = "(BackendUsingLegacyKeyArrays == -1 || BackendUsingLegacyKeyArrays == 0) && \"Backend needs to either only use io.AddKeyEvent(), " ascii /* score: '19.00'*/
      $s16 = "(flags & 0x0F) == 0 && \"Misuse of legacy hardcoded ImDrawCornerFlags values!\"" fullword ascii /* score: '19.00'*/
      $s17 = "(io.KeysDown[n] == false || IsKeyDown((ImGuiKey)n)) && \"Backend needs to either only use io.AddKeyEvent(), either only fill leg" ascii /* score: '19.00'*/
      $s18 = "D:\\Projets\\Installer\\Installer-master\\Installer\\imgui\\imgui_widgets.cpp" fullword ascii /* score: '18.00'*/
      $s19 = "blogger" fullword ascii /* score: '18.00'*/
      $s20 = "dumpster" fullword ascii /* score: '18.00'*/
   condition:
	  pe.imphash() == "0f8a99886eefb08f79a1070b706fdc7e" or
      uint16(0) == 0x754e and filesize < 5000KB and
      8 of them
}
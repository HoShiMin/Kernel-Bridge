#include "pch.h"

#include "WdkTypes.h"
#include "CtlTypes.h"
#include "FltTypes.h"
#include "User-Bridge.h"
#include "Rtl-Bridge.h"

#include <fltUser.h>
#include "CommPort.h"
#include "Flt-Bridge.h"

#include "Kernel-Tests.h"

#include <vector>
#include <string>
#include <iostream>
#include <set>

#define _NO_CVCONST_H
#include <dbghelp.h>
#include "SymParser.h"

void RunTests() {
    BeeperTest tBeeper(L"Beeper");
    IoplTest tIopl(L"IOPL");
    VirtualMemoryTest tVirtualMemory(L"VirtualMemory");
    MdlTest tMdl(L"Mdl");
    PhysicalMemoryTest tPhysicalMemory(L"PhysicalMemory");
    ProcessesTest tProcesses(L"Processes");
    ShellTest tShell(L"Shells");
    StuffTest tStuff(L"Stuff");
}


int main() {
    KbLoader::KbUnload();
    if (KbLoader::KbLoadAsFilter(
        L"C:\\Temp\\Kernel-Bridge\\Kernel-Bridge.sys",
        L"260000" // Altitude of minifilter
    )) {
        for (int i = 0; i < 1; i++) {
            WdkTypes::HMODULE hModule = NULL;
            KbRtl::KbLdrStatus LdrStatus = KbRtl::KbLoadModuleFile(L"C:\\Temp\\Kernel-Bridge\\KbLoadableModule.dll", L"LdMd", &hModule);
            if (LdrStatus == KbRtl::KbLdrSuccess) {
                LoadableModules::KbCallModule(hModule, 1, 0x11223344);
                LoadableModules::KbCallModule(hModule, 2, 0x1EE7C0DE);
                LoadableModules::KbUnloadModule(hModule);
            }

            RunTests();
        }
        KbLoader::KbUnload();
    } else {
        std::wcout << L"Unable to load driver!" << std::endl;
    }

    std::wcout << L"Press any key to exit..." << std::endl;
    std::cin.get();
}
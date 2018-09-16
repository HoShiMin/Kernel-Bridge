# The Kernel-Bridge Framework
The "Kernel-Bridge" project is a Windows kernel driver template, development framework and
kernel-mode API and wrappers written on C++17.  
  
### ✔ It supports work with:
* IO-ports (+ 'in/out/cli/sti' usermode forwarding by IOPL)
* System beeper
* MSRs, CPUID, TSC and performance counters (RDPMC)
* DMI/SMBIOS memory reading
* Physical memory (RW, mappings)
* Kernel memory management (allocations, mappings, transitions)
* Usermode memory management (allocations in processes etc.)
* Direct UM->KM and KM->UM memory transitions
* Obtaining processes/threads handles from kernel
* Reading and writing memory of another processes
* Suspending/resuming/termination processes
* Creating kernel and usermode threads
* Memory mappings between usermode and kernel
* Remote code execution (APCs delivery)
* Execution of custom usermode shellcodes
* Unsigned drivers mapping
* Processes, threads, handles and modules usermode callbacks (`ObRegisterCallbacks` & `PsSet***NotifyRoutine`)
  
### ➰ In development and coming soon:
* PCI configuration (is it really necessary?)
* Minifilter with usermode callbacks
* PDB parsing and AsmJIT integration
  
Driver template has full support of C++ static and global initializers and all of C++17 features (without C++ exceptions). All of API modules are easy-to-use and have no external dependiencies, so you can include them to your own C++ drivers. All of API functions are grouped into a logical categories into namespaces, so you can quickly find all functions you want.
  
### 💦 Driver template has:
* Support of METHOD_BUFFERED, METHOD_IN/OUT_DIRECT and METHOD_NEITHER
* Minifilter loading and filtering routines templates
* SAL-annotations and well-documented API
* Ready-to-use IOCTLs handling routine
* Static Driver Verifier tests passing
  
### 💨 Building and using:  
Download [Microsoft Visual Studio Community](https://visualstudio.microsoft.com/downloads/) and [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).  
For driver testing use [VMware Player](https://my.vmware.com/en/web/vmware/free#desktop_end_user_computing/vmware_workstation_player/14_0).  
For load an unsigned drivers you should to enable Test-mode of Windows and disable signs checkings:
```
- Disable signatures checkings (allow to install unsigned drivers):
bcdedit.exe /set loadoptions DISABLE_INTEGRITY_CHECKS
bcdedit.exe /set TESTSIGNING ON

- Enable signatures checkings (deny to install unsigned drivers):
bcdedit.exe /set loadoptions ENABLE_INTEGRITY_CHECKS
bcdedit.exe /set TESTSIGNING OFF

- Enable support of kernel debugger (WinDbg and Kernel Debugger from WDK):
bcdedit.exe /debug on   -  enable support of kernel debugging
bcdedit.exe /debug off  -  disable it
```
  
#### Communication with usermode apps:  
For communication with usermode you should use "User-Bridge" wrappers as standalone \*.cpp/\*.h modules or as \*.dll.  
All required headers are `WdkTypes.h`, `CtlTypes.h` and `User-Bridge.h`:
```cpp
#include <Windows.h>
 
#include "CtlTypes.h"
#include "User-Bridge.h"

// Loading as minifilter (it allows to use extended features):
KbLoader::KbLoadAsFilter(L"N:\\Folder\\Kernel-Bridge.sys", L"260000");

// ... Do what you want ...

KbLoader::KbUnload();
```
  
#### Files hierarchy:
`/User-Bridge/API/` - usermode API and wrappers for all functions of KB  
`/Kernel-Bridge/API/` - standalone kernel API for using in C++ drivers  
`/Kernel-Bridge/Kernel-Bridge/` - driver template files  
`/SharedTypes/` - shared types headers required for UM and KM modules  
`/Kernel-Tests/` - unit-tests for UM and KM modules and common functions  
  
#### Example (using of KbReadProcessMemory):
```cpp
#include <Windows.h>

#include "WdkTypes.h"
#include "CtlTypes.h"
#include "User-Bridge.h"

using namespace Processes::MemoryManagement;

...

constexpr int Size = 64;
UCHAR Buffer[Size] = {};
 
BOOL Status = KbReadProcessMemory(
    ProcessId,
    0x7FFF0000, // Desired address in context of ProcessId
    &Buffer,
    Size
);
```

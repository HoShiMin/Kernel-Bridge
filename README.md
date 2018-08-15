# The Kernel-Bridge Framework
The "Kernel-Bridge" project is a Windows kernel driver template, development framework and
kernel-mode API and wrappers written on C++17.  
  
### ✔ It support work with:
* IO-ports (+ 'in/out/cli/sti' usermode forwarding by IOPL)
* System beeper
* MSRs (CPU Model Specific Registers)
* CPUID, TSC and performance counters (RDPMC)
* DMI/SMBIOS memory reading
* Physical memory (RW, allocations and mappings)
* Kernel memory management (allocations, mappings, transitions)
* Usermode memory management (allocations in processes etc.)
* Direct UM->KM and KM->UM memory transitions
* Obtaining processes handles from kernel
* Reading and writing memory of another processes
* Suspending/resuming/termination processes
* Creating kernel and usermode threads
* Memory mappings between usermode and kernel

### ➰ In development and coming soon:
* PCI configuration
* Processes protection using ObRegisterCallbacks
* Minifilter with usermode callbacks
* Processes and modules usermode callbacks
* Execution of custom usermode shellcodes
* Unsigned drivers, kernel and usermode libraries mapping
* Usermode wrapper for all Kernel-Bridge functions
  
Driver template has full support of C++ static and global initializers and all of C++17 features (without C++ exceptions). All of API modules are easy-to-use and have no external dependiencies, so you can include them to your own C++ drivers. All of API functions are grouped into a logical categories into namespaces, so you can quickly find all functions you want.
  
### 💦 Driver template has:
* Support of METHOD_BUFFERED, METHOD_IN/OUT_DIRECT and METHOD_NEITHER
* Minifilter loading and filtering routines templates
* SAL-annotations and well-documented API
* Ready-to-use IOCTLs handling routine
* HLK tests passing
  
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
For communication with usermode you can use a `DriversUtils.h` from "DriversUtils" folder that have a functions to install a driver and communicate with it using DeviceIoControl. You can directly include `CtlTypes.h` from "Kernel-Bridge/Kernel-Bridge/" folder to your usermode app for using Kernel-Bridge data types for requests.
  
Example (using of KbReadProcessMemory):
```
#include <Windows.h>
#include <winternl.h>

#include "DriversUtils.h"
#include "CtlTypes.h"

...

InstallDriver(
    L"N:\\Path\\To\\Driver.sys",
    L"Kernel-Bridge"
);

HANDLE hDriver = OpenDevice(L"\\\\.\\Kernel-Bridge");

const int Size = 64;
BYTE Buffer[Size];

// Filling the input struct:
KB_READ_WRITE_PROCESS_MEMORY_IN Input = {};
Input.ProcessId = 1234; // Desired process
Input.BaseAddress = 0x7FFF000; // Desired address you want to read
Input.Buffer = static_cast<PVOID>(Buffer);
Input.Size = Size;

// 0x800 = base, 41 = index of KbReadProcessMemory (look at the IOCTLHandlers.cpp):
constexpr int CTL_READ_PROCESS_MEMORY = IOCTL(0x800 + 41, METHOD_NEITHER);

// Sending request:
SendIOCTL(
    hDriver,
    CTL_READ_PROCESS_MEMORY,
    &Input,
    sizeof(Input),
    NULL,
    0
);
```

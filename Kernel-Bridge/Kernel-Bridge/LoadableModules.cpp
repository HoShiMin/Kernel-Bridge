#include <wdm.h>
#include <stdarg.h>
#include <ntstrsafe.h>

#include "../API/Locks.h"
#include "../API/StringsAPI.h"
#include "../API/LinkedList.h"
#include "../API/MemoryUtils.h"

#include "LoadableModules.h"

class ModulesStorage {
private:
    using MODULE_INFO = struct {
        WideString ModuleName;
        PVOID hModule;
        OPTIONAL LoadableModules::_OnUnload OnUnload;
        OPTIONAL LoadableModules::_OnDeviceControl OnDeviceControl;
        OPTIONAL LoadableModules::_OnException OnException;
        Atomic32 Refcount;
        PRKEVENT CompletionEvent;
        volatile bool Unloading;
    };

    FastMutex Lock;
    LinkedList<MODULE_INFO> Modules;
public:
    ModulesStorage() : Lock(), Modules() {}
    ~ModulesStorage() {
        Lock.Lock();
        if (Modules.IsEmpty()) {
            Lock.Unlock();
            return;
        }

        LinkedList<MODULE_INFO>::ListIterator it = Modules.begin();
        while (it != Modules.end()) {
            auto Entry = it.GetEntry();
            ++it;
            auto Module = Entry->GetValue();

            if (!Module->Unloading) {
                Module->Unloading = true;
                KeWaitForSingleObject(Module->CompletionEvent, Executive, KernelMode, FALSE, NULL);
                if (Module->OnUnload) {
                    __try {
                        Module->OnUnload();
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        KdPrint(("Kernel-Bridge]: Exception catched in %ws.OnUnload!\r\n", Module->ModuleName.GetData()));
                    }
                }
                VirtualMemory::FreePoolMemory(Module->hModule);
                Modules.Remove(Entry);
            }
        }
        Lock.Unlock();
    }

    NTSTATUS Load(
        PVOID hModule,
        LPCWSTR ModuleName,
        OPTIONAL LoadableModules::_OnLoad OnLoad = NULL,
        OPTIONAL LoadableModules::_OnUnload OnUnload = NULL,
        OPTIONAL LoadableModules::_OnDeviceControl OnDeviceControl = NULL,
        OPTIONAL LoadableModules::_OnException OnException = NULL
    ) {
        if (!hModule || !ModuleName) return STATUS_INVALID_PARAMETER;

        WideString Name(ModuleName);
        Name.Trim().ToLowerCase();
        if (!Name.GetLength()) return STATUS_INVALID_PARAMETER;

        BOOLEAN AlreadyLoaded = FALSE;
        Lock.Lock();
        for (auto& Module : Modules) {
            AlreadyLoaded = Module.hModule == hModule || Module.ModuleName == Name;
            if (AlreadyLoaded) break;
        }
        Lock.Unlock();
        
        if (AlreadyLoaded) 
            return STATUS_ALREADY_COMPLETE;

        NTSTATUS Status = STATUS_SUCCESS;
        ULONG ExceptionCode = 0;
        PEXCEPTION_POINTERS ExceptionPointers = NULL;
        if (OnLoad) {
            __try {
                Status = OnLoad(hModule, ModuleName);
            } __except (
                ExceptionCode = GetExceptionCode(),
                ExceptionPointers = GetExceptionInformation(),
                EXCEPTION_EXECUTE_HANDLER    
            ) {
                KdPrint(("[Kernel-Bridge]: Exception 0x%X catched in %ws.OnLoad!\r\n", ExceptionCode, ModuleName));
                if (OnException) {
                    __try {
                        return OnException(ExceptionCode, ExceptionPointers);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        KdPrint(("[Kernel-Bridge]: Exception catched in %ws.OnException!\r\n", ModuleName));
                        // Double fault, but we return the first exception:
                        return ExceptionCode;
                    }
                }
                return ExceptionCode;
            }
        }

        if (Status == STATUS_SUCCESS) {
            Lock.Lock();
            MODULE_INFO Module = {};
            Module.ModuleName = Name;
            Module.hModule = hModule;
            Module.OnUnload = OnUnload;
            Module.OnDeviceControl = OnDeviceControl;
            Module.OnException = OnException;
            Module.CompletionEvent = new KEVENT;
            KeInitializeEvent(Module.CompletionEvent, NotificationEvent, TRUE);
            Modules.InsertTail(Module);
            Lock.Unlock();
        }

        return Status;
    }

    NTSTATUS Call(PVOID hModule, UINT64 CtlCode, OPTIONAL PVOID Argument = NULL) {
        if (!hModule) return STATUS_INVALID_PARAMETER;

        NTSTATUS Status = STATUS_NOT_FOUND;

        MODULE_INFO* TargetModule = NULL;

        Lock.Lock();
        if (Modules.IsEmpty()) {
            Lock.Unlock();
            return STATUS_NOT_FOUND;
        }

        for (auto& Module : Modules) {
            if (Module.hModule != hModule) continue;

            if (Module.Unloading) {
                Status = STATUS_NOT_FOUND;
                break;
            }

            if (!Module.OnDeviceControl) {
                Status = STATUS_NOT_IMPLEMENTED;
                break;
            }

            // Referencing module:
            if (Module.Refcount.Get() == 0)
                KeClearEvent(Module.CompletionEvent);
            Module.Refcount++;

            TargetModule = &Module;
            break;
        }
        Lock.Unlock();

        if (!TargetModule) return Status;

        ULONG ExceptionCode = 0;
        PEXCEPTION_POINTERS ExceptionPointers = NULL;
        __try {
            Status = TargetModule->OnDeviceControl(CtlCode, Argument);
        } __except (
            ExceptionCode = GetExceptionCode(),
            ExceptionPointers = GetExceptionInformation(),
            EXCEPTION_EXECUTE_HANDLER       
        ) {
            KdPrint(("[Kernel-Bridge]: Exception 0x%X catched in %ws.OnDeviceControl!\r\n", ExceptionCode, TargetModule->ModuleName.GetData()));
            Status = STATUS_UNSUCCESSFUL;
            if (TargetModule->OnException) {
                __try {
                    Status = TargetModule->OnException(ExceptionCode, ExceptionPointers);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    KdPrint(("[Kernel-Bridge]: Exception catched in %ws.OnException!\r\n", TargetModule->ModuleName.GetData()));
                    Status = ExceptionCode;
                }
            }
        }

        TargetModule->Refcount--;
        if (TargetModule->Refcount.Get() == 0)
            KeSetEvent(TargetModule->CompletionEvent, LOW_REALTIME_PRIORITY, FALSE);

        return Status;
    }

    NTSTATUS Unload(PVOID hModule) {
        if (!hModule) return STATUS_INVALID_PARAMETER;

        LinkedList<MODULE_INFO>::ListEntry* TargetEntry = NULL;
        
        Lock.Lock();
        if (Modules.IsEmpty()) {
            Lock.Unlock();
            return STATUS_NOT_FOUND;
        }

        LinkedList<MODULE_INFO>::ListIterator it = Modules.begin();
        while (it != Modules.end()) {
            auto Entry = it.GetEntry();
            ++it;
            auto Module = Entry->GetValue();

            if (Module->hModule != hModule) continue;
            if (Module->Unloading) break;

            Module->Unloading = true;
            TargetEntry = Entry;
            break;
        }
        Lock.Unlock();

        if (!TargetEntry) return STATUS_NOT_FOUND;

        MODULE_INFO* TargetModule = TargetEntry->GetValue();

        KeWaitForSingleObject(TargetModule->CompletionEvent, Executive, KernelMode, FALSE, NULL);
        if (TargetModule->OnUnload) {
            __try {
                TargetModule->OnUnload();
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                KdPrint(("Kernel-Bridge]: Exception catched in %ws.OnUnload!\r\n", TargetModule->ModuleName.GetData()));
            }
        }

        Lock.Lock();
        Modules.Remove(TargetEntry);
        delete TargetModule->CompletionEvent;
        Lock.Unlock();
        
        VirtualMemory::FreePoolMemory(hModule);
        return STATUS_SUCCESS;
    }

    PVOID GetModuleHandle(LPCWSTR ModuleName) {
        WideString Name(ModuleName);
        Name.Trim().ToLowerCase();
        if (!Name.GetLength()) return NULL;

        PVOID hModule = NULL;
        Lock.Lock();
        for (auto& Module : Modules) {
            if (Module.ModuleName == Name) hModule = Module.hModule;
            if (hModule) break;
        }
        Lock.Unlock();
        return hModule;
    }
};

namespace LoadableModules {
    static ModulesStorage Modules;

    NTSTATUS LoadModule(
        PVOID hModule,
        LPCWSTR ModuleName,
        OPTIONAL _OnLoad OnLoad,
        OPTIONAL _OnUnload OnUnload,
        OPTIONAL _OnDeviceControl OnDeviceControl,
        OPTIONAL _OnException OnException
    ) {
        return Modules.Load(hModule, ModuleName, OnLoad, OnUnload, OnDeviceControl, OnException);
    }

    NTSTATUS CallModule(PVOID hModule, UINT64 CtlCode, OPTIONAL PVOID Argument) {
        return Modules.Call(hModule, CtlCode, Argument);
    }

    NTSTATUS UnloadModule(PVOID hModule) {
        return Modules.Unload(hModule);
    }

    PVOID GetModuleHandle(LPCWSTR ModuleName) {
        return Modules.GetModuleHandle(ModuleName);
    }
}
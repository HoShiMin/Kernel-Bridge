#pragma once

#define PciGetAddress(Bus, Device, Function)    (((Bus & 0xFF) << 8) | ((Device & 0x1F) << 3) | (Function & 7))
#define PciGetBusNumber(Address)                ((Address >> 8) & 0xFF)
#define PciGetDeviceNumber(Address)             ((Address >> 3) & 0x1F)
#define PciGetFunctionNumber(Address)           (Address & 7)

namespace PCI {
    ULONG ReadPciConfig(
        ULONG PciAddress,
        ULONG PciOffset,
        PVOID Buffer,
        ULONG BufferSize
    );

    ULONG WritePciConfig(
        ULONG PciAddress,
        ULONG PciOffset,
        PVOID Buffer,
        ULONG BufferSize
    );
}
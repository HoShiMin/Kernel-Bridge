#include <ntddk.h>
#include "PCI.h"

namespace PCI {
    ULONG ReadPciConfig(
        ULONG PciAddress, 
        ULONG PciOffset, 
        PVOID Buffer, 
        ULONG BufferSize
    ) {
        PCI_SLOT_NUMBER SlotNumber = {};
        SlotNumber.u.bits.DeviceNumber   = PciGetDeviceNumber(PciAddress);
        SlotNumber.u.bits.FunctionNumber = PciGetFunctionNumber(PciAddress);

        ULONG BusNumber = PciGetBusNumber(PciAddress);
        return HalGetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber.u.AsULONG, Buffer, PciOffset, BufferSize);
    }

    ULONG WritePciConfig(
        ULONG PciAddress,
        ULONG PciOffset,
        PVOID Buffer,
        ULONG BufferSize
    ) {
        PCI_SLOT_NUMBER SlotNumber = {};
        SlotNumber.u.bits.DeviceNumber   = PciGetDeviceNumber(PciAddress);
        SlotNumber.u.bits.FunctionNumber = PciGetFunctionNumber(PciAddress);

        ULONG BusNumber = PciGetBusNumber(PciAddress);
        return HalSetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber.u.AsULONG, Buffer, PciOffset, BufferSize);
    }
}
#include <fltKernel.h>

#ifdef _X86_
// For compatibility with C++17, because <intrin.h> contains deprecated language statements:
extern "C" unsigned char __inbyte(unsigned short PortNumber);
extern "C" unsigned short __inword(unsigned short PortNumber);
extern "C" unsigned long __indword(unsigned short PortNumber);
extern "C" void __inbytestring(unsigned short PortNumber, unsigned char* Buffer, unsigned long Count);
extern "C" void __inwordstring(unsigned short PortNumber, unsigned short* Buffer, unsigned long Count);
extern "C" void __indwordstring(unsigned short PortNumber, unsigned long* Buffer, unsigned long Count);
extern "C" void __outbyte(unsigned short PortNumber, unsigned char Data);
extern "C" void __outword(unsigned short PortNumber, unsigned short Data);
extern "C" void __outdword(unsigned short PortNumber, unsigned long Data);
extern "C" void __outbytestring(unsigned short PortNumber, unsigned char* Buffer, unsigned long Count);
extern "C" void __outwordstring(unsigned short PortNumber, unsigned short* Buffer, unsigned long Count);
extern "C" void __outdwordstring(unsigned short PortNumber, unsigned long* Buffer, unsigned long Count);
#endif

namespace IO {
    namespace IOPL {
        constexpr unsigned int IoplAccessMask = 0x3000;

#ifdef _AMD64_
        PKTRAP_FRAME GetTrapFrame() {
            return reinterpret_cast<PKTRAP_FRAME>(
                reinterpret_cast<SIZE_T>(IoGetInitialStack()) - sizeof(KTRAP_FRAME)
            );
        }

        void RaiseIopl() {
            GetTrapFrame()->EFlags |= IoplAccessMask;
        }

        void ResetIopl() {
            GetTrapFrame()->EFlags &= ~IoplAccessMask;
        }
#elif _X86_
        // Offsets from: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/ktrap_frame.htm
        constexpr unsigned char KTrapFrame32Size = 0x8C;
        constexpr unsigned char EFlagsOffsetInKTrapFrame32 = 0x70;

        PVOID GetTrapFrame() {
            return reinterpret_cast<PVOID>(
                reinterpret_cast<SIZE_T>(IoGetInitialStack()) - KTrapFrame32Size
            );
        }

        PULONG GetEFlagsPtr(PVOID KTrapFramePtr) {
            return reinterpret_cast<PULONG>(
                reinterpret_cast<SIZE_T>(KTrapFramePtr) + EFlagsOffsetInKTrapFrame32    
            );
        }

        void RaiseIopl() {
            *GetEFlagsPtr(GetTrapFrame()) |= IoplAccessMask;
        }

        void ResetIopl() {
            *GetEFlagsPtr(GetTrapFrame()) &= ~IoplAccessMask;
        }
#endif
    }

    namespace Beeper {
        void SetBeeperRegime() {
            __outbyte(0x43, 0xB6);
        }

        void StartBeeper() {
            __outbyte(0x61, __inbyte(0x61) | 3);
        }

        void StopBeeper() {
            __outbyte(0x61, __inbyte(0x61) & 252);
        }

        void SetBeeperIn() {
            __outbyte(0x61, __inbyte(0x61) & 253);
        }

        void SetBeeperOut() {
            __outbyte(0x61, __inbyte(0x61) | 2);
        }

        void SetBeeperDivider(unsigned short Divider) {
            __outbyte(0x42, static_cast<unsigned char>(Divider));
            __outbyte(0x42, static_cast<unsigned char>(Divider >> 8));
        }

        void SetBeeperFrequency(unsigned short Frequency) {
            if (!Frequency) Frequency = 1;
            SetBeeperDivider(static_cast<unsigned short>(1193182 / static_cast<unsigned long>(Frequency)));
        }
    }

    namespace RW {
        unsigned char ReadPortByte(unsigned short PortNumber) {
            return __inbyte(PortNumber);
        }

        unsigned short ReadPortWord(unsigned short PortNumber) {
            return __inword(PortNumber);
        }

        unsigned long ReadPortDword(unsigned short PortNumber) {
            return __indword(PortNumber);
        }

        void ReadPortByteString(unsigned short PortNumber, unsigned char* Buffer, unsigned long Count) {
            return __inbytestring(PortNumber, Buffer, Count);
        }

        void ReadPortWordString(unsigned short PortNumber, unsigned short* Buffer, unsigned long Count) {
            return __inwordstring(PortNumber, Buffer, Count);
        }

        void ReadPortDwordString(unsigned short PortNumber, unsigned long* Buffer, unsigned long Count) {
            return __indwordstring(PortNumber, Buffer, Count);
        }

        void WritePortByte(unsigned short PortNumber, unsigned char Data) {
            __outbyte(PortNumber, Data);
        }

        void WritePortWord(unsigned short PortNumber, unsigned short Data) {
            __outword(PortNumber, Data);
        }

        void WritePortDword(unsigned short PortNumber, unsigned long Data) {
            __outdword(PortNumber, Data);
        }

        void WritePortByteString(unsigned short PortNumber, unsigned char* Buffer, unsigned long Count) {
            __outbytestring(PortNumber, Buffer, Count);
        }

        void WritePortWordString(unsigned short PortNumber, unsigned short* Buffer, unsigned long Count) {
            __outwordstring(PortNumber, Buffer, Count);
        }

        void WritePortDwordString(unsigned short PortNumber, unsigned long* Buffer, unsigned long Count) {
            __outdwordstring(PortNumber, Buffer, Count);
        }
    }
}
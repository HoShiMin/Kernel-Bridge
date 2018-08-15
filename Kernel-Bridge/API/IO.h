#pragma once

namespace IO {
    namespace IOPL {
        void RaiseIopl();
        void ResetIopl();
    }

    namespace Beeper {
        void SetBeeperRegime(); // Call this once before using beeper
        void StartBeeper();     // Enable beeper with setted frequency
        void StopBeeper();      // Disable beeper
        void SetBeeperIn();     // Reset voltage from beeper membrane
        void SetBeeperOut();    // Set voltage to beeper membrane
        void SetBeeperDivider(unsigned short Divider); // 1193182 Hz / Divider
        void SetBeeperFrequency(unsigned short Frequency);
    }

    namespace RW {
        unsigned char ReadPortByte(unsigned short PortNumber);
        unsigned short ReadPortWord(unsigned short PortNumber);
        unsigned long ReadPortDword(unsigned short PortNumber);
        void ReadPortByteString(unsigned short PortNumber, unsigned char* Buffer, unsigned long Count);
        void ReadPortWordString(unsigned short PortNumber, unsigned short* Buffer, unsigned long Count);
        void ReadPortDwordString(unsigned short PortNumber, unsigned long* Buffer, unsigned long Count);
        void WritePortByte(unsigned short PortNumber, unsigned char Data);
        void WritePortWord(unsigned short PortNumber, unsigned short Data);
        void WritePortDword(unsigned short PortNumber, unsigned long Data);
        void WritePortByteString(unsigned short PortNumber, unsigned char* Buffer, unsigned long Count);
        void WritePortWordString(unsigned short PortNumber, unsigned short* Buffer, unsigned long Count);
        void WritePortDwordString(unsigned short PortNumber, unsigned long* Buffer, unsigned long Count);
    }
}
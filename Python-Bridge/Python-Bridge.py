from ctypes import *


class KernelBridge:
    class Beeper:
        def __init__(self, kb):
            self.__kb = kb

        def set_beeper_regime(self):
            return self.__kb.KbSetBeeperRegime()

        def start_beeper(self):
            return self.__kb.KbStartBeeper()

        def stop_beeper(self):
            return self.__kb.KbStopBeeper()

        def set_beeper_in(self):
            return self.__kb.KbSetBeeperIn()

        def set_beeper_out(self):
            return self.__kb.KbSetBeeperOut()

        def set_beeper_divider(self, divider):
            return self.__kb.KbSetBeeperDivider(c_ushort(divider))

        def set_beeper_frequency(self, frequency):
            return self.__kb.KbSetBeeperFrequency(c_ushort(frequency))

    class IO:
        def __init__(self, kb):
            self.__kb = kb

        def read_port_byte(self, port_number):
            value = c_byte()
            status = self.__kb.KbReadPortByte(c_ushort(port_number), byref(value))
            return status, value

        def read_port_word(self, port_number):
            value = c_ushort()
            status = self.__kb.KbReadPortWord(c_ushort(port_number), byref(value))
            return status, value

        def read_port_dword(self, port_number):
            value = c_uint()
            status = self.__kb.KbReadPortDword(c_ushort(port_number), byref(value))
            return status, value

        def write_port_byte(self, port_number, byte_value):
            return self.__kb.KbWritePortByte(c_ushort(port_number), c_byte(byte_value))

        def write_port_word(self, port_number, word_value):
            return self.__kb.KbWritePortWord(c_ushort(port_number), c_byte(word_value))

        def write_port_dword(self, port_number, dword_value):
            return self.__kb.KbWritePortDword(c_ushort(port_number), c_byte(dword_value))

    class Iopl:
        def __init__(self, kb):
            self.__kb = kb

        def raise_iopl(self):
            return self.__kb.KbRaiseIopl()

        def reset_iopl(self):
            return self.__kb.KbResetIopl()

    class CPU:
        class CpuidInfo(Structure):
            _fields_ = [("EAX", c_uint),
                        ("EBX", c_uint),
                        ("ECX", c_uint),
                        ("EDX", c_uint)]

        def __init__(self, kb):
            self.__kb = kb

        def cli(self):
            return self.__kb.KbCli()

        def sti(self):
            return self.__kb.KbSti()

        def hlt(self):
            return self.__kb.KbHlt()

        def rdmsr(self, index):
            value = c_uint64()
            status = self.__kb.KbReadMsr(c_uint(index), byref(value))
            return status, value

        def wrmsr(self, index, value):
            return self.__kb.KbWriteMsr(c_uint(index), c_uint64(value))

        def cpuid(self, function_id_eax):
            info = self.CpuidInfo()
            status = self.__kb.KbCpuid(c_uint(function_id_eax), byref(info))
            return status, info

        def cpuidex(self, function_id_eax, subfunction_id_ecx):
            info = self.CpuidInfo()
            status = self.__kb.KbCpuidEx(c_uint(function_id_eax), c_uint(subfunction_id_ecx), byref(info))
            return status, info

        def rdpmc(self, index):
            value = c_uint64()
            status = self.__kb.KbReadPmc(c_uint(index), byref(value))
            return status, value

        def rdtsc(self):
            value = c_uint64()
            status = self.__kb.KbReadTsc(byref(value))
            return status, value

        def rdtscp(self):
            value = c_uint64()
            aux = c_uint()
            status = self.__kb.KbReadTsc(byref(value), byref(aux))
            return status, value, aux

    class VirtualMemory:
        def __init__(self, kb):
            self.__kb = kb

        def alloc_kernel_memory(self, size, executable):
            ptr = c_uint64()
            status = self.__kb.KbAllocKernelMemory(c_uint(size), c_byte(executable), byref(ptr))
            return status, ptr

        def free_kernel_memory(self, ptr):
            return self.__kb.KbFreeKernelMemory(c_uint64(ptr))

        def alloc_non_cached_memory(self, size):
            ptr = c_uint64()
            status = self.__kb.KbAllocNonCachedMemory(c_uint(size), byref(ptr))
            return status, ptr

        def free_non_cached_memory(self, ptr, size):
            return self.__kb.KbFreeNonCachedMemory(c_uint64(ptr), c_uint(size))

        def copy_move_memory(self, dst, src, size, intersects):
            return self.__kb.KbCopyMoveMemory(c_uint64(dst), c_uint64(src), c_uint(size), c_byte(intersects))

        def fill_memory(self, ptr, filler, size):
            return self.__kb.KbFillMemory(c_uint64(ptr), c_byte(filler), c_uint(size))

        def equal_memory(self, src, dst, size):
            equals = c_byte()
            status = self.__kb.KbEqualMemory(c_uint64(src), c_uint64(dst), c_uint(size), byref(equals))
            return status, equals

    def __init__(self, dll="User-Bridge.dll"):
        self.__kb = WinDLL(dll)
        self.beeper = self.Beeper(self.__kb)
        self.io = self.IO(self.__kb)
        self.iopl = self.Iopl(self.__kb)
        self.cpu = self.CPU(self.__kb)

    def load_as_driver(self, driver_path):
        return self.__kb.KbLoadAsDriver(c_wchar_p(driver_path))

    def load_as_filter(self, driver_path, altitude='260000'):
        return self.__kb.KbLoadAsFilter(c_wchar_p(driver_path), c_wchar_p(altitude))

    def unload(self):
        return self.__kb.KbUnload()

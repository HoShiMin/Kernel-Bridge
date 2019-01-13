# Ensure to run it as Administrator!

import enum
from ctypes import *


class KernelBridge:
    __api_version = 8

    class KProcessorMode(enum.Enum):
        kernel_mode = 0
        user_mode = 1
        maximum_mode = 2

    class LockOperation(enum.Enum):
        io_read_access = 0
        io_write_access = 1
        io_modify_access = 2

    class MemoryCachingTypeOrig(enum.Enum):
        mm_frame_buffer_cached = 2

    class MemoryCachingType(enum.Enum):
        mm_non_cached = 0
        mm_cached = 1
        mm_write_combined = 2
        mm_hardware_coherent_cached = 3
        mm_non_cached_unordered = 4
        mm_uswc_cached = 5
        mm_maximum_cache_type = 6
        mm_non_mapped = -1

    class SectionInherit(enum.Enum):
        view_share = 1
        view_unmap = 2

    class ObjFlags(enum.Enum):
        obj_inherit = 0x00000002
        obj_permanent = 0x00000010
        obj_exclusive = 0x00000020
        obj_case_insensitive = 0x00000040
        obj_openif = 0x00000080
        obj_openlink = 0x00000100
        obj_kernel_handle = 0x00000200
        obj_force_access_check = 0x00000400
        obj_ignore_impersonated_devicemap = 0x00000800
        obj_dont_reparse = 0x00001000
        obj_valid_attributes = 0x00001FF2

    class ClientId(Structure):
        _fields_ = [("ProcessId", c_uint64),
                    ("ThreadId", c_uint64)]

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

    class Mdl:
        def __init__(self, kb):
            self.__kb = kb

        def allocate_mdl(self, virtual_address, size):
            mdl = c_uint64()
            status = self.__kb.KbAllocateMdl(c_uint64(virtual_address), c_uint(size), byref(mdl))
            return status, mdl

        def probe_and_lock_pages(self, pid, mdl, processor_mode, lock_operation):
            return self.__kb.KbProbeAndLockPages(
                c_uint(pid),
                c_uint64(mdl),
                c_uint(processor_mode),
                c_uint(lock_operation)
            )

        def map_mdl(self, src_pid, dst_pid, mdl, need_probe_and_lock, map_to_address_space,
                    protect, cache_type, user_requested_address):
            ptr = c_uint64()
            status = self.__kb.KbMapMdl(
                byref(ptr),
                c_uint64(src_pid),
                c_uint64(dst_pid),
                c_uint64(mdl),
                c_byte(need_probe_and_lock),
                c_uint(map_to_address_space),
                c_uint(protect),
                c_uint(cache_type),
                c_uint64(user_requested_address)
            )
            return status, ptr

        def protect_mapped_memory(self, mdl, protect):
            return self.__kb.KbProtectMappedMemory(c_uint64(mdl), c_uint(protect))

        def unmap_mdl(self, mdl, mapped_memory, need_unlock):
            return self.__kb.KbUnmapMdl(c_uint64(mdl), c_uint64(mapped_memory), c_byte(need_unlock))

        def unlock_pages(self, mdl):
            return self.__kb.KbUnlockPages(c_uint64(mdl))

        def free_mdl(self, mdl):
            return self.__kb.KbFreeMdl(c_uint64(mdl))

        class MappingInfo(Structure):
            _fields_ = [("MappedAddress", c_uint64),
                        ("Mdl", c_uint64)]

        def map_memory(self, src_pid, dst_pid, virtual_address, size, map_to_address_space,
                       protect, cache_type, user_requested_address):
            mapping_info = self.MappingInfo()
            status = self.__kb.KbMapMemory(
                byref(mapping_info),
                c_uint64(src_pid),
                c_uint64(dst_pid),
                c_uint64(virtual_address),
                c_uint(size),
                c_uint(map_to_address_space),
                c_uint(protect),
                c_uint(cache_type),
                c_uint64(user_requested_address)
            )
            return status, mapping_info

        def unmap_memory(self, mapping_info):
            return self.__kb.KbUnmapMemory(byref(mapping_info))

    class PhysicalMemory:
        def __init__(self, kb):
            self.__kb = kb

        def alloc_physical_memory(self, lowest_acceptable, highest_acceptable, boundary_multiple, size, caching_type):
            ptr = c_uint64()
            status = self.__kb.KbAllocPhysicalMemory(
                c_uint64(lowest_acceptable),
                c_uint64(highest_acceptable),
                c_uint64(boundary_multiple),
                c_uint(size),
                c_uint(caching_type)
            )
            return status, ptr

        def free_physical_memory(self, address):
            return self.__kb.KbFreePhysicalMemory(c_uint64(address))

        def map_physical_memory(self, physical_address, size, caching_type):
            ptr = c_uint64()
            status = self.__kb.KbMapPhysicalMemory(c_uint64(physical_address), c_uint(size), c_uint(caching_type))
            return status, ptr

        def unmap_physical_memory(self, virtual_address, size):
            return self.__kb.KbUnmapPhysicalMemory(c_uint64(virtual_address), c_uint(size))

        def get_physical_address(self, process, virtual_address):
            ptr = c_uint64()
            status = self.__kb.KbGetPhysicalAddress(c_uint64(process), c_uint64(virtual_address), byref(ptr))
            return status, ptr

        def get_virtual_for_physical(self, physical_address):
            ptr = c_uint64()
            status = self.__kb.KbGetVirtualForPhysical(c_uint64(physical_address), byref(ptr))
            return status, ptr

        def read_physical_memory(self, physical_address, buffer, size, caching_type):
            return self.__kb.KbReadPhysicalMemory(
                c_uint64(physical_address),
                c_void_p(buffer),
                c_uint(size),
                c_uint(caching_type)
            )

        def write_physical_memory(self, physical_address, buffer, size, caching_type):
            return self.__kb.KbWritePhysicalMemory(
                c_uint64(physical_address),
                c_void_p(buffer),
                c_uint(size),
                c_uint(caching_type)
            )

        def read_dmi_memory(self, buffer, size):
            return self.__kb.KbReadDmiMemory(c_void_p(buffer), c_uint(size))

    class Processes:
        def __init__(self, kb):
            self.__kb = kb

        def get_eprocess(self, pid):
            peprocess = c_uint64()
            status = self.__kb.KbGetEprocess(c_uint64(pid), byref(peprocess))
            return status, peprocess

        def get_ethread(self, pid):
            pethread = c_uint64()
            status = self.__kb.KbGetEthread(c_uint64(pid), byref(pethread))
            return status, pethread

        def open_process(self, pid, access_mask, obj_attributes):
            handle = c_uint64()
            status = self.__kb.KbOpenProcess(c_uint64(pid), byref(handle), c_uint(access_mask), c_uint(obj_attributes))
            return status, handle

        def open_process_by_ptr(self, peprocess, access_mask, obj_attributes, processor_mode):
            handle = c_uint64()
            status = self.__kb.KbOpenProcessByPointer(
                c_uint64(peprocess),
                byref(handle),
                c_uint(access_mask),
                c_uint(obj_attributes),
                c_uint(processor_mode)
            )
            return status, handle

        def open_thread(self, tid, access_mask, obj_attributes):
            handle = c_uint64()
            status = self.__kb.KbOpenThread(c_uint64(tid), byref(handle), c_uint(access_mask), c_uint(obj_attributes))
            return status, handle

        def open_thread_by_ptr(self, pethread, access_mask, obj_attributes, processor_mode):
            handle = c_uint64()
            status = self.__kb.KbOpenThreadByPointer(
                c_uint64(pethread),
                byref(handle),
                c_uint(access_mask),
                c_uint(obj_attributes),
                c_uint(processor_mode)
            )
            return status, handle

        def dereference_object(self, object_ptr):
            return self.__kb.KbDereferenceObject(c_uint64(object_ptr))

        def close_handle(self, handle):
            return self.__kb.KbCloseHandle(c_uint64(handle))

        def query_information_process(self, handle, info_class, buffer, size, return_length):
            return self.__kb.KbQueryInformationProcess(
                c_uint64(handle),
                c_uint(info_class),
                c_void_p(buffer),
                c_uint(size),
                byref(return_length)
            )

        def set_information_process(self, handle, info_class, buffer, size):
            return self.__kb.KbSetInformationProcess(
                c_uint64(handle),
                c_uint(info_class),
                c_void_p(buffer),
                c_uint(size)
            )

        def query_information_thread(self, handle, info_class, buffer, size, return_length):
            return self.__kb.KbQueryInformationThread(
                c_uint64(handle),
                c_uint(info_class),
                c_void_p(buffer),
                c_uint(size),
                byref(return_length)
            )

        def set_information_thread(self, handle, info_class, buffer, size):
            return self.__kb.KbSetInformationThread(
                c_uint64(handle),
                c_uint(info_class),
                c_void_p(buffer),
                c_uint(size)
            )

        def create_user_thread(self, pid, routine, arg, create_suspended):
            client = KernelBridge.ClientId()
            handle = c_uint64()
            status = self.__kb.KbCreateUserThread(
                c_uint(pid),
                c_uint64(routine),
                c_uint64(arg),
                c_uint(create_suspended),
                byref(client),
                byref(handle)
            )
            return status, client, handle

        def create_system_thread(self, pid, routine, arg):
            client = KernelBridge.ClientId()
            handle = c_uint64()
            status = self.__kb.KbCreateSystemThread(
                c_uint(pid),
                c_uint64(routine),
                c_uint64(arg),
                byref(client),
                byref(handle)
            )
            return status, client, handle

        def suspend_process(self, pid):
            return self.__kb.KbSuspendProcess(c_uint(pid))

        def resume_process(self, pid):
            return self.__kb.KbResumeProcess(c_uint(pid))

        def get_thread_context(self, tid, context, context_size, processor_mode):
            return self.__kb.KbGetThreadContext(
                c_uint(tid),
                c_void_p(context),
                c_uint(context_size),
                c_uint(processor_mode)
            )

        def set_thread_context(self, tid, context, context_size, processor_mode):
            return self.__kb.KbSetThreadContext(
                c_uint(tid),
                c_void_p(context),
                c_uint(context_size),
                c_uint(processor_mode)
            )

        def alloc_user_memory(self, pid, protect, size):
            ptr = c_uint64()
            status = self.__kb.KbAllocUserMemory(c_uint(pid), c_uint(protect), c_uint(size), byref(ptr))
            return status, ptr

        def free_user_memory(self, pid, ptr):
            return self.__kb.KbFreeUserMemory(c_uint(pid), c_uint64(ptr))

        def secure_virtual_memory(self, pid, ptr, size, protect):
            handle = c_uint64()
            status = self.__kb.KbSecureVirtualMemory(
                c_uint(pid),
                c_uint64(ptr),
                c_uint(size),
                c_uint(protect),
                byref(handle)
            )
            return status, handle

        def unsecure_virtual_memory(self, pid, secure_handle):
            return self.__kb.KbUnsecureVirtualMemory(c_uint(pid), c_uint64(secure_handle))

        def read_process_memory(self, pid, address, buffer, size, access_mode):
            return self.__kb.KbReadProcessMemory(
                c_uint(pid),
                c_uint64(address),
                c_void_p(buffer),
                c_uint(size),
                c_uint(access_mode)
            )

        def write_process_memory(self, pid, address, buffer, size, access_mode, perform_copy_on_write):
            return self.__kb.KbWriteProcessMemory(
                c_uint(pid),
                c_uint64(address),
                c_void_p(buffer),
                c_uint(size),
                c_uint(access_mode),
                c_byte(perform_copy_on_write)
            )

        def get_process_cr3_cr4(self, pid):
            cr3 = c_uint64()
            cr4 = c_uint64()
            status = self.__kb.KbGetProcessCr3Cr4(c_uint(pid), byref(cr3), byref(cr4))
            return status, cr3, cr4

        def queue_user_apc(self, tid, routine, arg):
            return self.__kb.KbQueueUserApc(c_uint(tid), c_uint64(routine), c_uint64(arg))

    class Sections:
        def __init__(self, kb):
            self.__kb = kb

        def create_section(self, name, max_size, access, obj_flags, protection, allocation_attributes, hfile):
            handle = c_uint64()
            status = self.__kb.KbCreateSection(
                byref(handle),
                c_wchar_p(name),
                c_uint64(max_size),
                c_uint(access),
                c_uint(obj_flags),
                c_uint(protection),
                c_uint(allocation_attributes),
                c_uint64(hfile)
            )
            return status, handle

        def open_section(self, name, access, obj_flags):
            handle = c_uint64()
            status = self.__kb.KbOpenSection(byref(handle), c_wchar_p(name), c_uint(access), c_uint(obj_flags))
            return status, handle

        def map_view_of_section(
                self,
                hsection,
                hprocess,
                desired_base_address,
                commit_size,
                desired_section_offset,
                desired_view_size,
                section_inherit,
                allocation_type,
                protect
        ):
            ptr = c_uint64(desired_base_address)
            offset = c_uint64(desired_section_offset)
            view_size = c_uint64(desired_view_size)
            status = self.__kb.KbMapViewOfSection(
                c_uint64(hsection),
                c_uint64(hprocess),
                byref(ptr),
                c_uint(commit_size),
                byref(offset),
                byref(view_size),
                c_uint(section_inherit),
                c_uint(allocation_type),
                c_uint(protect)
            )
            return status, ptr, offset, view_size

        def unmap_view_of_section(self, hprocess, base_address):
            return self.__kb.KbUnmapViewOfSection(c_uint64(hprocess), c_uint64(base_address))

    class KernelShells:
        def __init__(self, kb):
            self.__kb = kb

        def execute_shell_code(self, routine, arg):
            result = c_uint()
            status = self.__kb.KbExecuteShellCode(c_void_p(routine), c_void_p(arg), byref(result))
            return status, result

    class LoadableModules:
        def __init__(self, kb):
            self.__kb = kb

        def create_driver(self, driver_name, driver_entry):
            return self.__kb.KbCreateDriver(c_wchar_p(driver_name), c_uint64(driver_entry))

        def load_module(self, hmodule, module_name, on_load, on_unload, on_device_control):
            return self.__kb.KbLoadModule(
                c_uint64(hmodule),
                c_wchar_p(module_name),
                c_uint64(on_load),
                c_uint64(on_unload),
                c_uint64(on_device_control)
            )

        def unload_module(self, hmodule):
            return self.__kb.KbUnloadModule(c_uint64(hmodule))

        def get_module_handle(self, module_name):
            hmodule = c_uint64()
            status = self.__kb.KbGetModuleHandle(c_wchar_p(module_name), byref(hmodule))
            return status, hmodule

        def call_module(self, hmodule, ctl_code, arg):
            return self.__kb.KbCallModule(c_uint64(hmodule), c_uint(ctl_code), c_uint64(arg))

    class Pci:
        def __init__(self, kb):
            self.__kb = kb

        def read_pci_config(self, pci_address, pci_offset, buffer, size):
            bytes_read = c_uint()
            status = self.__kb.KbReadPciConfig(
                c_uint(pci_address),
                c_uint(pci_offset),
                c_void_p(buffer),
                c_uint(size),
                byref(bytes_read)
            )
            return status, bytes_read

        def write_pci_config(self, pci_address, pci_offset, buffer, size):
            bytes_written = c_uint()
            status = self.__kb.KbWritePciConfig(
                c_uint(pci_address),
                c_uint(pci_offset),
                c_void_p(buffer),
                c_uint(size),
                byref(bytes_written)
            )
            return status, bytes_written

    class Hypervisor:
        def __init__(self, kb):
            self.__kb = kb

        def vmm_enable(self):
            return self.__kb.KbVmmEnable()

        def vmm_disable(self):
            return self.__kb.KbVmmDisable()

    class Stuff:
        def __init__(self, kb):
            self.__kb = kb

        def get_kernel_proc_address(self, routine_name):
            ptr = c_uint64()
            status = self.__kb.KbGetKernelProcAddress(c_wchar_p(routine_name), byref(ptr))
            return status, ptr

        def stall_execution_processor(self, microseconds):
            return self.__kb.KbStallExecutionProcessor(c_uint(microseconds))

        def bugcheck(self, error_code):
            return self.__kb.KbBugCheck(c_uint(error_code))

        def find_signature(self, pid, memory, size, sig, mask):
            found_address = c_uint64()
            status = self.__kb.KbFindSignature(
                c_uint(pid),
                c_uint64(memory),
                c_uint(size),
                c_char_p(sig),
                c_char_p(mask),
                byref(found_address)
            )
            return status, found_address

    def __init__(self, dll="User-Bridge.dll"):
        self.__kb = WinDLL(dll)
        self.beeper = self.Beeper(self.__kb)
        self.io = self.IO(self.__kb)
        self.iopl = self.Iopl(self.__kb)
        self.cpu = self.CPU(self.__kb)
        self.virtual_memory = self.VirtualMemory(self.__kb)
        self.mdl = self.Mdl(self.__kb)
        self.physical_memory = self.PhysicalMemory(self.__kb)
        self.processes = self.Processes(self.__kb)
        self.sections = self.Sections(self.__kb)
        self.kernel_shells = self.KernelShells(self.__kb)
        self.loadable_modules = self.LoadableModules(self.__kb)
        self.pci = self.Pci(self.__kb)
        self.hypervisor = self.Hypervisor(self.__kb)
        self.stuff = self.Stuff(self.__kb)

    def load_as_driver(self, driver_path):
        return self.__kb.KbLoadAsDriver(c_wchar_p(driver_path))

    def load_as_filter(self, driver_path, altitude='260000'):
        return self.__kb.KbLoadAsFilter(c_wchar_p(driver_path), c_wchar_p(altitude))

    def unload(self):
        return self.__kb.KbUnload()

    def get_driver_api_version(self):
        return self.__kb.KbGetDriverApiVersion()

    def get_user_api_version(self):
        return self.__kb.KbGetUserApiVersion()

    def get_python_api_version(self):
        return self.__api_version

    def get_handles_count(self):
        count = c_uint()
        status = self.__kb.KbGetHandlesCount(byref(count))
        return status, count

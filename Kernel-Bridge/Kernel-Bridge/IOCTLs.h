#pragma once

#define IOCTL(Code, Method) (CTL_CODE(0x8000, (Code), Method, FILE_ANY_ACCESS))
#define EXTRACT_CTL_CODE(Ioctl)   ((unsigned short)(((Ioctl) & 0b0011111111111100) >> 2))
#define EXTRACT_CTL_METHOD(Ioctl) ((unsigned short)((Ioctl) & 0b11))

#define CTL_BASE (0x800)
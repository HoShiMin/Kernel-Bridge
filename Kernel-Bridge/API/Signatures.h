#pragma once

// pattern = "\x11\x22\x00\x33\x00\x00\x44"
// mask = "..?.??."
// finds 0x11 0x22 ?? 0x33 ?? ?? 0x44, where ?? is any byte.

void* find_signature(void* memory, size_t size, const char* pattern, const char* mask);
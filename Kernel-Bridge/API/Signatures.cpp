#include <string.h>

void* find_signature(void* memory, size_t size, const char* pattern, const char* mask) 
{
    size_t sig_length = strlen(mask);
    if (sig_length > size) return nullptr;

    for (size_t i = 0; i < size - sig_length; i++)
    {
        bool found = true;
        for (size_t j = 0; j < sig_length; j++)
            found &= mask[j] == '?' || pattern[j] == *((char*)memory + i + j);

        if (found) 
            return (char*)memory + i;
    }
    return nullptr;
}
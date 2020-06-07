#include "Stopwatch.h"

#include <ntifs.h>

Stopwatch::Stopwatch()
    : m_begin(0)
    , m_end(0)
    , m_freq(0)
{
    KeQueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&m_freq));
}

Stopwatch::Stopwatch(bool init)
    : m_begin(0)
    , m_end(0)
    , m_freq(0)
{
    if (init)
    {
        start();
    }
}

void Stopwatch::reset()
{
    m_begin = 0;
    m_end = 0;
    KeQueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&m_freq));
}

void Stopwatch::start()
{
    m_begin = KeQueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&m_freq)).QuadPart;
    m_end = m_begin;
}

float Stopwatch::stop()
{
    m_end = KeQueryPerformanceCounter(NULL).QuadPart;
    return delta();
}

float Stopwatch::delta()
{
    return static_cast<float>(m_end - m_begin) / m_freq;
}
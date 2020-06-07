#pragma once

class Stopwatch
{
protected:
    unsigned long long m_begin, m_end;
    unsigned long long m_freq;

public:
    Stopwatch();
    Stopwatch(bool init);

    void reset();

    void start();
    float stop();

    float delta();
};
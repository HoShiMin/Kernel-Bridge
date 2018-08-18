#pragma once

class KernelTests {
private:
    std::wstring TestName;
protected:
    bool Passed;
public:
    virtual bool RunTest() {
        std::wcout << L"Null test" << std::endl;
        return true;
    }

    KernelTests(LPCWSTR Name) : TestName(Name), Passed(false) {
        std::wcout << L"[ " << TestName << " ] Test started..." << std::endl;
    }

    ~KernelTests() {
        std::wcout << L"[ " << (Passed ? L"PASSED" : L"FAILED") << L" ] " << TestName << std::endl; 
    }

    void Log(LPCWSTR Text) {
        std::wcout << L"\t[ " << TestName << L" ]: " << Text << std::endl; 
    }
};

class BeeperTest : public KernelTests {
public:
    BeeperTest(LPCWSTR Name) : KernelTests(Name) { Passed = RunTest(); }
    bool RunTest() override;
};

class IoplTest : KernelTests {
public:
    IoplTest(LPCWSTR Name) : KernelTests(Name) { Passed = RunTest(); }
    bool RunTest() override;
};

class VirtualMemoryTest : KernelTests {
public:
    VirtualMemoryTest(LPCWSTR Name) : KernelTests(Name) { Passed = RunTest(); }
    bool RunTest() override;
};

class MdlTest : KernelTests {
public:
    MdlTest(LPCWSTR Name) : KernelTests(Name) { Passed = RunTest(); }
    bool RunTest() override;
};

class PhysicalMemoryTest : KernelTests {
public:
    PhysicalMemoryTest(LPCWSTR Name) : KernelTests(Name) { Passed = RunTest(); }
    bool RunTest() override;
};

class ProcessesTest : KernelTests {
public:
    ProcessesTest(LPCWSTR Name) : KernelTests(Name) { Passed = RunTest(); }
    bool RunTest() override;
};
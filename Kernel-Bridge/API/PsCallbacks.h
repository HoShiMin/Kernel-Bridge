#pragma once

class PsProcessCallback {
private:
    PCREATE_PROCESS_NOTIFY_ROUTINE Callback;
public:
    PsProcessCallback(const PsProcessCallback&) = delete;
    PsProcessCallback(PsProcessCallback&&) = delete;
    PsProcessCallback& operator = (const PsProcessCallback&) = delete;
    PsProcessCallback& operator = (PsProcessCallback&&) = delete;

    PsProcessCallback();
    PsProcessCallback(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyCallback);
    ~PsProcessCallback();

    NTSTATUS SetupCallback(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyCallback);
    VOID RemoveCallback();
};

class PsThreadCallback {
private:
    PCREATE_THREAD_NOTIFY_ROUTINE Callback;
public:
    PsThreadCallback(const PsThreadCallback&) = delete;
    PsThreadCallback(PsThreadCallback&&) = delete;
    PsThreadCallback& operator = (const PsThreadCallback&) = delete;
    PsThreadCallback& operator = (PsThreadCallback&&) = delete;

    PsThreadCallback();
    PsThreadCallback(PCREATE_THREAD_NOTIFY_ROUTINE NotifyCallback);
    ~PsThreadCallback();

    NTSTATUS SetupCallback(PCREATE_THREAD_NOTIFY_ROUTINE NotifyCallback);
    VOID RemoveCallback();
};

class PsImageCallback {
private:
    PLOAD_IMAGE_NOTIFY_ROUTINE Callback;
public:
    PsImageCallback(const PsImageCallback&) = delete;
    PsImageCallback(PsImageCallback&&) = delete;
    PsImageCallback& operator = (const PsImageCallback&) = delete;
    PsImageCallback& operator = (PsImageCallback&&) = delete;

    PsImageCallback();
    PsImageCallback(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyCallback);
    ~PsImageCallback();

    NTSTATUS SetupCallback(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyCallback);
    VOID RemoveCallback();
};
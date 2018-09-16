#include <fltKernel.h>

#include "PsCallbacks.h"

PsProcessCallback::PsProcessCallback() : Callback(NULL) {}

PsProcessCallback::PsProcessCallback(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyCallback) : PsProcessCallback() {
    SetupCallback(NotifyCallback);
}

PsProcessCallback::~PsProcessCallback() {
    RemoveCallback();
}

NTSTATUS PsProcessCallback::SetupCallback(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyCallback) {
    if (!NotifyCallback) return STATUS_INVALID_PARAMETER;
    if (Callback) RemoveCallback();

    NTSTATUS Status = PsSetCreateProcessNotifyRoutine(NotifyCallback, FALSE);
    if (NT_SUCCESS(Status)) Callback = NotifyCallback;
    return Status;
}

VOID PsProcessCallback::RemoveCallback() {
    if (!Callback) return;
    PsSetCreateProcessNotifyRoutine(Callback, TRUE);
    Callback = NULL;
}



PsThreadCallback::PsThreadCallback() : Callback(NULL) {}

PsThreadCallback::PsThreadCallback(PCREATE_THREAD_NOTIFY_ROUTINE NotifyCallback) : PsThreadCallback() {
    SetupCallback(NotifyCallback);
}

PsThreadCallback::~PsThreadCallback() {
    RemoveCallback();
}

NTSTATUS PsThreadCallback::SetupCallback(PCREATE_THREAD_NOTIFY_ROUTINE NotifyCallback) {
    if (!NotifyCallback) return STATUS_INVALID_PARAMETER;
    if (Callback) RemoveCallback();

    NTSTATUS Status = PsSetCreateThreadNotifyRoutine(NotifyCallback);
    if (NT_SUCCESS(Status)) Callback = NotifyCallback;
    return Status;
}

VOID PsThreadCallback::RemoveCallback() {
    if (!Callback) return;
    PsRemoveCreateThreadNotifyRoutine(Callback);
    Callback = NULL;
}



PsImageCallback::PsImageCallback() : Callback(NULL) {}

PsImageCallback::PsImageCallback(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyCallback) : PsImageCallback() {
    SetupCallback(NotifyCallback);
}

PsImageCallback::~PsImageCallback() {
    RemoveCallback();
}

NTSTATUS PsImageCallback::SetupCallback(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyCallback) {
    if (!NotifyCallback) return STATUS_INVALID_PARAMETER;
    if (Callback) RemoveCallback();

    NTSTATUS Status = PsSetLoadImageNotifyRoutine(NotifyCallback);
    if (NT_SUCCESS(Status)) Callback = NotifyCallback;
    return Status;
}

VOID PsImageCallback::RemoveCallback() {
    if (!Callback) return;
    PsRemoveLoadImageNotifyRoutine(Callback);
    Callback = NULL;
}
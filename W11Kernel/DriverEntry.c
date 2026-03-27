#include <ntifs.h>
#include "Debug.h"

extern NTSTATUS HookShadowSSDT();
extern NTSTATUS UnhookShadowSSDT();
extern NTSTATUS StartWorkerThread();
extern NTSTATUS StopWorkerThread();

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    //UnhookShadowSSDT();
    
    // --------------------------------------------

    StopWorkerThread();

    DebugMessage("[W11Kernel] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DebugMessage("Hello from driver!\n");

    UNREFERENCED_PARAMETER(RegistryPath);

    if (DriverObject != NULL)
    {
        DriverObject->DriverUnload = DriverUnload;
    }
    else
    {
        DebugMessage("[W11Kernel] DriverObject is NULL!\n");
    }

    DebugMessage("[W11Kernel] Driver loaded\n");

    //HookShadowSSDT();

    // ------------------------------------------

    StartWorkerThread();

    return STATUS_SUCCESS;
}
#include <ntifs.h>

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

    DbgPrint("[W11Kernel] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrint("Hello from driver!\n");

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[W11Kernel] Driver loaded\n");

    //HookShadowSSDT();

    // ------------------------------------------

    StartWorkerThread();

    return STATUS_SUCCESS;
}
#include "KernelIncludes.h"
#include <stdlib.h>

const LARGE_INTEGER g_StateIntervals[2] = {
    {.QuadPart = -20000000 },   // 2秒
    {.QuadPart = -10000000 }     // 0.1秒
};

// 全局变量
PETHREAD g_hWorkerThread = NULL;
CONNECTION_STATE g_CurrentState = STATE_DISCONNECTED;
//LARGE_INTEGER g_CurrentInterval = { -20000000 } ;
// -----------------------
volatile BOOLEAN g_bRunning = FALSE;

// 启动工作线程
NTSTATUS StartWorkerThread()
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES threadAttr;
    InitializeObjectAttributes(&threadAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    g_bRunning = TRUE;
    TransitionToState(STATE_DISCONNECTED);

    status = PsCreateSystemThread(
        &g_hWorkerThread,
        THREAD_ALL_ACCESS,
        &threadAttr,
        NULL,
        NULL,
        WorkerThreadRoutine,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        g_bRunning = FALSE;
        g_hWorkerThread = NULL;
        DbgPrint("Failed to create worker thread: 0x%X\n", status);
        return status;
    }

    DbgPrint("Worker thread started\n");
    return STATUS_SUCCESS;
}

// 停止工作线程
NTSTATUS StopWorkerThread()
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!g_hWorkerThread)
        return STATUS_NOT_FOUND;

    // 通知线程退出
    g_bRunning = FALSE;

    // 等待线程结束
    status = ZwWaitForSingleObject(g_hWorkerThread, FALSE, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwWaitForSingleObject failed: 0x%X\n", status);
    }

    // 关闭线程句柄
    ZwClose(g_hWorkerThread);
    g_hWorkerThread = NULL;

    ReleaseSharedData();

    DbgPrint("Worker thread stopped successfully.\n");

    return STATUS_SUCCESS;
}

// Worker线程函数
VOID WorkerThreadRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    InsertJunkCodeRND();
    TransitionToState(STATE_DISCONNECTED);

    while (g_bRunning)
    {
        InsertJunkCode(1);
        NTSTATUS status;

        switch (g_CurrentState)
        {
        case STATE_DISCONNECTED:
            InsertJunkCode(2);
            status = TryConnectSharedMemory();
            if (NT_SUCCESS(status) && g_CurrentState != STATE_CONNECTED)
            {
                TransitionToState(STATE_CONNECTED);
            }
            break;

        case STATE_CONNECTED:
            InsertJunkCode(3);
            status = CheckAndProcessCommand();
            if (!NT_SUCCESS(status) && g_CurrentState != STATE_DISCONNECTED)
            {
                TransitionToState(STATE_DISCONNECTED);
            }
            break;
        }
        InsertJunkCodeRND();
        // 添加随机扰动
        LARGE_INTEGER nextInterval = AddRandomJitterSafe(g_StateIntervals[g_CurrentState], 10);

        // PASSIVE_LEVEL安全延时
        KeDelayExecutionThread(KernelMode, FALSE, &nextInterval);
    }

    InsertJunkCodeRND();
    PsTerminateSystemThread(STATUS_SUCCESS);
}


VOID TransitionToState(CONNECTION_STATE newState)
{
    DbgPrint("State transition: %d -> %d\n", g_CurrentState, newState);
    g_CurrentState = newState;
    //g_CurrentInterval = g_StateIntervals[newState];
}

LARGE_INTEGER AddRandomJitterSafe(LARGE_INTEGER baseInterval, int jitterPercent)
{
    LARGE_INTEGER result = baseInterval;

    // 取绝对值方便计算
    LONGLONG absBase = labs(baseInterval.QuadPart);

    // 计算 ±jitterPercent 范围
    LONGLONG jitterRange = absBase * jitterPercent / 100;

    if (jitterRange > 0)
    {
        // 使用简单伪随机：可以用 perfCount 生成一个小于 jitterRange 的值
        LARGE_INTEGER perfCount = KeQueryPerformanceCounter(NULL);
        LONGLONG randomOffset = perfCount.QuadPart % (2 * jitterRange + 1); // 0 ~ 2*jitterRange
        randomOffset -= jitterRange; // -jitterRange ~ +jitterRange

        result.QuadPart += randomOffset;
    }

    // 打印 baseInterval 原始值
    DbgPrint("AddRandomJitterSafeFromTicks -> baseInterval.QuadPart=%lld\n", baseInterval.QuadPart);

    // 打印基准、扰动和最终结果
    //DbgPrint("AddRandomJitterSafeFromTicks -> result=%lld (~%llu ms)\n", result.QuadPart, (unsigned long long)(-result.QuadPart / 10000));

    return result;
}
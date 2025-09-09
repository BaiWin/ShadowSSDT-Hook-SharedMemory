#pragma once
#include "KernelIncludes.h"

typedef enum
{
    STATE_DISCONNECTED,      // 未连接状态，低频检测
    STATE_CONNECTED          // 已连接，高频数据交换
} CONNECTION_STATE;

extern CONNECTION_STATE g_CurrentState;

// 当前实际使用的间隔
//extern LARGE_INTEGER g_CurrentInterval;

NTSTATUS StartWorkerThread();

NTSTATUS StopWorkerThread();

VOID WorkerThreadRoutine(PVOID Context);

VOID TransitionToState(CONNECTION_STATE newState);

LARGE_INTEGER AddRandomJitterSafe(LARGE_INTEGER baseInterval, int jitterPercent);   // 10%
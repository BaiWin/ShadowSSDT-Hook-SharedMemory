#pragma once
#include "KernelIncludes.h"

NTSTATUS InitShadowSSDT();
VOID RestoreShadowSSDT();
NTSTATUS UnhookShadowSSDT();
NTSTATUS HookShadowSSDT();

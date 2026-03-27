#pragma once

#include <ntdef.h>     // 先包含基础类型定义
#include <ntimage.h>   // PE结构体依赖以上

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <string.h>
#endif

// 项目的头文件
#include "Comm.h"
#include "Util.h"
#include "HookFunction.h"
#include "ModuleBase.h"
#include "PatternScan.h"
#include "ShadowSSDT.h"
#include "NtDllMapper.h"
#include "SharedMemory.h"
#include "WorkerThread.h"
#include "Encrypt.h"
#include "Disguise.h"
#include "JunkCode.h"
#include "Debug.h"|
#include "CR3Shuffling.h"
#include "Local.h"

#define ERROR_VALUE 0xFFFFFFFF
#define SHADOW_SSDT
//#define SSDT
#define WRITE_IN_GAP


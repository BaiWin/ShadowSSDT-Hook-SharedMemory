#pragma once
#include "KernelIncludes.h"

void WriteFormattedLog(const CHAR* Format, ...);

NTSTATUS WriteLogToFile(const CHAR* Message);
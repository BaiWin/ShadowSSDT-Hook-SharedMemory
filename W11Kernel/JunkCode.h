#pragma once

typedef VOID(*JunkCodeFunc)();

#ifdef _KERNEL_MODE
extern VOID JunkCode1();
extern VOID JunkCode2();
extern VOID JunkCode3();
#else
extern "C" {
    VOID JunkCode1();
    VOID JunkCode2();
    VOID JunkCode3();
}
#endif

// 函数数组（共用）
static JunkCodeFunc JunkCodeFuncs[] = {
    JunkCode1,
    JunkCode2,
    JunkCode3
};

// C 语言 junk code（客户端）
#ifndef _KERNEL_MODE
__forceinline void InsertCCodeJunk(ULONG seed)
{
    volatile int dummy = seed % 7;
    dummy = (dummy << 3) ^ 0xABCD;
    if (dummy & 1) dummy += 0x1234;
}
#endif

// 执行机器码 junk code
__forceinline VOID ExecuteJunkCode(ULONG seed)
{
    ULONG index = seed % (sizeof(JunkCodeFuncs) / sizeof(JunkCodeFuncs[0]));
    JunkCodeFunc func = JunkCodeFuncs[index];
    func();
}

// 插入 junk code（偏移）
__forceinline VOID InsertJunkCode(ULONG offset)
{
#ifdef _KERNEL_MODE
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    ULONG seed = time.LowPart;
#else
    ULONG seed = (ULONG)time(NULL);
#endif
    ExecuteJunkCode(seed + offset);
}

// 插入 junk code（随机）
__forceinline VOID InsertJunkCodeRND()
{
#ifdef _KERNEL_MODE
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    ULONG seed = time.LowPart;
    ExecuteJunkCode(RtlRandom(&seed));
#else
    ULONG seed = (ULONG)time(NULL);
    ExecuteJunkCode(rand());
    InsertCCodeJunk(seed); // 客户端混合 C 语言 junk
#endif
}
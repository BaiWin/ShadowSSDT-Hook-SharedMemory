// test_listbox_console.cpp
#include <windows.h>
#include <iostream>

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

using pNtUserGetListBoxInfo_t = NTSTATUS(WINAPI*)(HWND);
using pRtlGetLastNtStatus_t = NTSTATUS(WINAPI*)(void);

int main_test()
{
    // 创建一个隐藏窗口作为父窗口
    HWND hwndParent = CreateWindowExW(
        0, L"STATIC", L"Parent", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 100, 100,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    if (!hwndParent)
    {
        std::cout << "CreateWindowExW failed, gle=" << GetLastError() << "\n";
        getchar();
        return -1;
    }

    // 创建一个 ListBox 子窗口
    HWND hwndList = CreateWindowExW(
        0, L"LISTBOX", NULL,
        WS_CHILD | WS_VISIBLE | LBS_NOTIFY | LBS_STANDARD,
        0, 0, 200, 100,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (!hwndList)
    {
        std::cout << "CreateWindowExW LISTBOX failed, gle=" << GetLastError() << "\n";
        getchar();
        return -1;
    }

    // 向 ListBox 添加一些项
    SendMessageW(hwndList, LB_ADDSTRING, 0, (LPARAM)L"Item A");
    SendMessageW(hwndList, LB_ADDSTRING, 0, (LPARAM)L"Item B");

    // --- 1. 测试 user32 的 GetListBoxInfo ---
    SetLastError(0);
    DWORD res = GetListBoxInfo(hwndList);
    DWORD gle = GetLastError();
    std::cout << "[user32] GetListBoxInfo -> " << res
        << ", GetLastError=" << gle << "\n";

    // --- 2. 测试 win32u 的 NtUserGetListBoxInfo ---
    HMODULE hWin32u = LoadLibraryW(L"win32u.dll");
    if (hWin32u)
    {
        auto NtUserGetListBoxInfo =
            (pNtUserGetListBoxInfo_t)GetProcAddress(hWin32u, "NtUserGetListBoxInfo");
        if (NtUserGetListBoxInfo)
        {
            SetLastError(0);
            NTSTATUS st = NtUserGetListBoxInfo(hwndList);
            DWORD gle2 = GetLastError();

            // 尝试获取 RtlGetLastNtStatus
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            NTSTATUS stLast = 0;
            if (hNtdll)
            {
                auto RtlGetLastNtStatus =
                    (pRtlGetLastNtStatus_t)GetProcAddress(hNtdll, "RtlGetLastNtStatus");
                if (RtlGetLastNtStatus)
                {
                    stLast = RtlGetLastNtStatus();
                }
            }

            std::cout << "[win32u] NtUserGetListBoxInfo -> NTSTATUS=0x"
                << std::hex << st << std::dec
                << ", GetLastError=" << gle2
                << ", RtlGetLastNtStatus=0x" << std::hex << stLast << std::dec
                << "\n";
        }
        else
        {
            std::cout << "NtUserGetListBoxInfo not exported in win32u.dll\n";
        }
    }
    else
    {
        std::cout << "Failed to load win32u.dll\n";
    }

    DestroyWindow(hwndList);
    DestroyWindow(hwndParent);
    getchar();

    return 0;
}
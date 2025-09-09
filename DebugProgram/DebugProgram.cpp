#include <iostream>
#include <windows.h>

int global_int = 123456;

int main()
{
    HMODULE hBase = GetModuleHandle(NULL);
    uintptr_t base = reinterpret_cast<uintptr_t>(hBase);
    uintptr_t addr = reinterpret_cast<uintptr_t>(&global_int);
    while (true)
    {
        // offset 0x5034
        std::cout << "Baseaddress- " << std::hex << hBase << " offset- " << std::hex << addr - base << std::endl;
        std::cout << "address- " << std::hex << addr << " value- " << std::dec << global_int << std::endl;
        Sleep(2000);
    }
}


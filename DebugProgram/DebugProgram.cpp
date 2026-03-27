#include <iostream>
#include <windows.h>

int global_int = 123456;

float viewMatrix4x4[16] = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, };

int main()
{
    global_int = 12345;
    HMODULE hBase = GetModuleHandle(NULL);
    uintptr_t base = reinterpret_cast<uintptr_t>(hBase);
    uintptr_t addr = reinterpret_cast<uintptr_t>(&global_int);
    uintptr_t matrix = reinterpret_cast<uintptr_t>(&viewMatrix4x4);
    while (true)
    {
        // offset 
        std::cout << "Baseaddress- " << std::hex << hBase << " offset- " << std::hex << addr - base << std::endl;
        std::cout << "address- " << std::hex << addr << " value- " << std::dec << global_int << std::endl;
        std::cout << "viewMatrix4x4- " << std::hex << matrix << std::endl;
        Sleep(2000);
    }
}


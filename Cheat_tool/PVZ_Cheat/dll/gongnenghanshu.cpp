#pragma once
#include "pch.h"
#include "Allhanshudef.h"
using namespace std;

//===========================================================================


void Change_Sun()
{
    DWORD dwPid = GetCurrentProcessId();
    HANDLE hTS = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hTS, &me))
    {
        printf("成功\n");
        printf("find modBaseAddr->0x%p\n", me.modBaseAddr);
    }
    else error();
    CloseHandle(hTS);
    DWORD lpBaseAddress = (DWORD)me.modBaseAddr;//获得基地址
    /////////////////////
    lpBaseAddress += 0x2A9EC0;
    LPVOID sun_addr = read_addr_chain((LPVOID)lpBaseAddress, dwPid);

    while (1) {
        int flag;
        printf("输入-1退出这个功能: ");
        scanf_s("%d", &flag);
        if (flag == -1) break;

        if (write_sun(dwPid, sun_addr) == 0) {
            printf("修改失败\n");
        }
        Sleep(0);
    }


    return;
}
LPVOID read_addr_chain(LPVOID addr, DWORD Pid)
{
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    DWORD addr1 = 0;

    if (!ReadProcessMemory(hprocess, addr, &addr1, 4, NULL)) { cout << "地址链读取失败" << endl; return NULL; }
    addr1 += 0x768;
    DWORD addr2 = 0;
    if (!ReadProcessMemory(hprocess, (LPVOID)addr1, &addr2, 4, NULL)) { cout << "地址链读取失败" << endl; return NULL; }

    addr2 += 0x5560;
    DWORD addr3 = addr2;
    //if(!ReadProcessMemory(hprocess, (LPVOID)addr2, &addr3, 4, NULL)) { cout << "地址链读取失败" << endl; exit(-1); }

    CloseHandle(hprocess);
    return (LPVOID)addr3;
}
int  write_sun(DWORD dPid, LPVOID lpBaseAddress)
{

    /////////
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dPid);
    ////////
    printf("Find lpBaseAddress of sun is->0x%p\n", lpBaseAddress);
    int number_of_sun = 0;
    if (!ReadProcessMemory(hProcess, lpBaseAddress, &number_of_sun, sizeof(int), NULL)) { std::cout << "error" << std::endl; return NULL; }
    printf("现阳光为->%d\n", number_of_sun);
    ///////////////////
    printf("请你写入想要修改阳光数->");
    int write_number_of_sun = 100;
    scanf_s("%d", &write_number_of_sun);

    if (!WriteProcessMemory(hProcess, lpBaseAddress, &write_number_of_sun, sizeof(int), NULL)) { printf("修改失败\n"); return NULL; }

    printf("修改成功！阳光数为->%d\n", write_number_of_sun);
    CloseHandle(hProcess);

    return 1;
}
void error()
{
    std::cout << "执行失败_错误代码->" << GetLastError() << std::endl;
    return;
}

void AddresToLittleendian(DWORD address, BYTE* chucun)
{
    for (int i = 0; i < 4; i++)
    {
        chucun[i] = address % 0x100;  // 256 = 1字节
        address /= 0x100;
    }
}

void Write_code(DWORD address, DWORD size_of_data, BYTE* data)
{
    DWORD oldProtect = 0;
    if (!VirtualProtect((LPVOID)address, size_of_data, PAGE_EXECUTE_READWRITE, &oldProtect)) { printf("权限修改失败\n");  return; }
    for (int i = 0; i < size_of_data; i++)
    {
        *(BYTE*)(address + i) = data[i];
    }
    FlushInstructionCache(GetCurrentProcess(),
        (LPCVOID)address,
        size_of_data);
    if (!VirtualProtect((LPVOID)address, size_of_data, oldProtect, &oldProtect)) { printf("权限修改回来失败\n");  return; }
}
DWORD jmp_back = 0x52D9E8;//0052D9E8
void __declspec(naked)fuzhicaozuo()
{

    __asm {
        mov[ecx + 0x28], 03
        fld dword ptr[ecx + 0x2C]
        push edi
        fisub[ecx + 0x08]
        jmp jmp_back
    }//七字节

}

DWORD_PTR Create_executable_memory(DWORD size_)//创建可执行代码区域
{
    void* mem = NULL;
    mem = VirtualAlloc(NULL, size_, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) { error(); return 0; }
    return (DWORD_PTR)mem;
}


void WritecodeToMemry(void* address, DWORD size_of_num, BYTE* zhili)
{
    for (int i = 0; i < size_of_num; i++)
    {
        *((BYTE*)address + i) = zhili[i];
    }
}


void Instant_Kill_Plantzombies()
{
    
    static BYTE OldZhili[7];   // 保存原始字节
    static bool saved = false; // 是否已保存
    if (!saved)
    {
        memcpy(OldZhili, (void*)0x52D9E1, 7);  // 只执行一次
        saved = true;
    }

    if (*(BYTE*)(0x52D9E1) != 0xE9)
    {
        DWORD pianyi = (DWORD)fuzhicaozuo - 5 - 0x52D9E1;
        BYTE dizhi[4];
        AddresToLittleendian(pianyi, dizhi);
        BYTE zhili[7] = { 0xE9,0,0,0,0,0x66,0x90 };
        for (int i = 0; i < 4; i++)
            zhili[i + 1] = dizhi[i];
        Write_code(0x52D9E1, 7, zhili);
        printf("开启秒杀\n");
        Sleep(1000);
    }
    else
    {
        Write_code(0x52D9E1, 7, OldZhili);
        printf("关闭秒杀\n");
        Sleep(1000);
    }

}

void Plant_no_cooldown()
{
    static BYTE OldZhili[2];
    static bool save = false;
    if (!save)
    {
        memcpy_s(OldZhili, 2, (void*)0x487296, 2);
        save = true;
    }
    if (*(BYTE*)0x487296 == 0x7E)
    {
        BYTE zhili[2] = { 0x90,0x90 };
        Write_code(0x487296, 2, zhili);
        printf("开启了无冷却\n");
        Sleep(500);
    }
    else
    {
        Write_code(0x487296, 2, OldZhili);
        printf("关闭无冷却\n");
        Sleep(500);
    }
}

void No_planting_limit()//目标地址0x40FE2F
{
    static BYTE OldZhili[6];
    static bool save = false;
    if (!save)
    {
        memcpy_s(OldZhili, 6, (void*)0x40FE2F, 6);
        save = true;
    }
    if (*(BYTE*)0x40FE2F == 0x0F)
    {
        BYTE zhili[6] = {0xE9, 0x20, 0x09, 0x00, 0x00, 0x90};
        Write_code(0x40FE2F, 6, zhili);
        printf("开启了种植无限制\n");
        Sleep(500);
    }
    else
    {
        Write_code(0x40FE2F, 6, OldZhili);
        printf("关闭种植无限制\n");
        Sleep(500);
    }
}

//返回申请内存地址           原地址               覆盖指令的大小          新指令          新指令大小不包括跳回指令                           储存原指令
void * HookToNewMemory(DWORD_PTR Old_Address, DWORD size_of_OldZhili, BYTE* NewZhili, DWORD size_of_NewZhili/*作用指令大小，不包括跳转指令*/, BYTE* OldZhili)
{
    DWORD_PTR NewMem_Address = Create_executable_memory(size_of_NewZhili + 5);//计算好新区域指令
    BYTE* NewMem_Address_ = (BYTE*)NewMem_Address;
    for (int i = 0; i < size_of_NewZhili; i++)
        NewMem_Address_[i] = NewZhili[i];
    DWORD Pianyi1 = Old_Address + size_of_OldZhili - (NewMem_Address + size_of_NewZhili) - 5;
    BYTE Jmp_back[5] = { 0xE9,0 ,0, 0, 0 };
    AddresToLittleendian(Pianyi1, &Jmp_back[1]);
    for (int i = 0; i < 5; i++)
        NewMem_Address_[size_of_NewZhili + i] = Jmp_back[i];

    DWORD Pianyi2 = NewMem_Address - Old_Address - 5;//计算好跳转指令
    BYTE* JmpToNewAddress = (BYTE*)malloc(size_of_OldZhili);
    JmpToNewAddress[0] = 0xE9;
    AddresToLittleendian(Pianyi2, &JmpToNewAddress[1]);
    for (int i = 5; i < size_of_OldZhili; i++)
        JmpToNewAddress[i] = 0x90;

    static bool saved = false; // 是否已保存
    if (!saved)
    {
        memcpy(OldZhili, (void*)Old_Address, size_of_OldZhili);  // 只执行一次
        saved = true;
    }

    Write_code(Old_Address, size_of_OldZhili, JmpToNewAddress);//写入到原地址
    free(JmpToNewAddress);

    return (void *)NewMem_Address;
}
void Release_all_zombies()
{
    static BYTE OldZhili[7];
    static bool flag = false;
    static void* NewMem_Address = NULL;
    if (!flag) 
    {
        BYTE NewZhili[17] = { 0xC7, 0x87, 0x9C, 0x55, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x83, 0x87, 0x9C, 0x55, 0x00, 0x00, 0xFF };
        NewMem_Address = HookToNewMemory(0x413E45, 7, NewZhili, 17, OldZhili);
        flag = true;
        printf("开启了僵尸全员出动\n");
        Sleep(500);
    }
    else
    {
        Write_code(0x413E45, 7, OldZhili);
        VirtualFree(NewMem_Address,0, MEM_RELEASE);
        NewMem_Address = NULL;
        flag = false;
        printf("关闭了僵尸全员出动\n");
        Sleep(500);
    }

}

//void Release_all_zombies()//00413E45目标区域 C7 87 9C 55 00 00 01 00 00 00      //83 87 9C 55 00 00 FF=================================
//{
//
//    DWORD_PTR executable_memory = 0;
//    executable_memory = Create_executable_memory(22);//申请空间
//    DWORD pianyi = executable_memory - 5 - 0x413E45;//计算偏移
//    BYTE jmp[4] = { 0 };
//    AddresToLittleendian(pianyi, jmp);
//    BYTE allzhili[7] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90 };
//    for (int i = 0; i < 4; i++)
//        allzhili[i + 1] = jmp[i];
//    Write_code(0x413E45, 7, allzhili);//写入跳转指令 
//    BYTE yunxingzhili[22] = { 0xC7, 0x87, 0x9C, 0x55, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x83, 0x87, 0x9C, 0x55, 0x00, 0x00, 0xFF };
//    BYTE jmp_back[5] = { 0xE9,0,0,0,0 };//跳回指令  00413E4C
//    pianyi = 0x413E4C - 5 - (executable_memory + 17);
//    AddresToLittleendian(pianyi, &jmp_back[1]);
//    for (int i = 0; i < 5; i++)
//        yunxingzhili[17 + i] = jmp_back[i];
//
//    WritecodeToMemry((void*)executable_memory, 22, yunxingzhili);
//}

void Plant_plants(unsigned int x, unsigned int y, unsigned int kind)
{
    __asm {
        pushad
        mov eax, 0x6a9ec0
        mov eax, [eax]
        add eax, 0x768
        mov ecx, [eax]
        push - 1
        push kind
        mov eax, y
        push x
        push ecx
        mov edx, 0x0040d120
        call edx
        popad

    }
}

void CreateConsole()
{
    AllocConsole();
    FILE* pStdout;
    freopen_s(&pStdout, "CONOUT$", "w", stdout);
    FILE* pStdin;
    freopen_s(&pStdin, "CONIN$", "r", stdin);
    SetConsoleTitleA("植物大战僵尸修改器");
}
void PlantRow(int y, int kind)
{
    for (int x = 0; x < 9; x++)
    {
        Plant_plants(x, y, kind);
        Sleep(50);
    }
}

void Plant_Plants()
{
    int flag = 0;
    int x = 0, y = 0, kind = 0;
    while (1)
    {
        printf("开始输入植物，输入-1退出\n");
        scanf_s("%d", &flag);
        if (flag == -1)
            break;
        printf("\n请输入x坐标->"); scanf_s("%u", &x); if (x >= 5 || x < 0) { printf("太大了，重新输入\n"); continue; }
        printf("\n请输入y坐标->"); scanf_s("%u", &y); if (y >= 5 || y < 0) { printf("太大了，重新输入\n"); continue; }
        printf("\n请输入植物代号->"); scanf_s("%u", &kind); if (kind > 50 || kind < 0) { printf("没那个植物，重新输入\n"); continue; }
        Plant_plants(x, y, kind);
        Sleep(0);
    }
}

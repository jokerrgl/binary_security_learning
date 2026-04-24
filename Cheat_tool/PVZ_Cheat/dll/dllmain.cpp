// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdio.h>
#include <iostream>
#include <iomanip> // 用于对齐
#include "Allhanshudef.h"
using namespace std;

HMODULE G_hModule = NULL;
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, TEXT("注入成功"), TEXT("注入成功"), MB_OK);
        G_hModule = hModule;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)maingames, 0, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


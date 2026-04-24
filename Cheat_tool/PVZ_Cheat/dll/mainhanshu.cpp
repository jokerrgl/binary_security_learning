#pragma once
#include "pch.h"
#include <stdio.h>
#include <iostream>
#include <iomanip> // 用于对齐
#include "Allhanshudef.h"

extern HMODULE G_hModule;

/////////////////////////////////////////////////=============================================================
void menu()
{
    printf("|================================================\n");
    printf("|请选择你要输入的序号,输入-1退出\n");
    printf("|1->修改阳光\n");
    printf("|2->种植植物\n");
    printf("|3->开启或关闭卡槽无冷却\n");
    printf("|4->开启或关闭种植无限制\n");
    printf("|5->开启或者关闭僵尸秒杀\n");
    printf("|6->开启或关闭僵尸全员出动\n");
    printf("|================================================\n");
}

DWORD WINAPI maingames(LPVOID lpParam)//主函数的实现
{
    CreateConsole();

    while (1)
    {
        menu();//菜单
        int index = 0;
        if (scanf_s("%d", &index) != 1) {
            // 清空输入缓冲区里的错误内容
            while (getchar() != '\n');
            printf("输入错误，请输入数字！\n");
            Sleep(500); // 短暂停留，让用户看到提示
            system("cls");
            continue; // 跳过本次循环，重新显示菜单
        }
        if (index != -1)
        {
            switch (index)
            {
            case 1:Change_Sun(); break;     //开关选择     <-增加选项===================================
            case 2:Plant_Plants(); break;
            case 3:Plant_no_cooldown(); break;
            case 4:No_planting_limit(); break;
            case 5:Instant_Kill_Plantzombies(); break;
            case 6:Release_all_zombies(); break;
            default:printf("输入错误\n");
            }
        }
        else break;
        Sleep(0);
        system("cls");
    }
    FreeConsole();
    return 0;
}


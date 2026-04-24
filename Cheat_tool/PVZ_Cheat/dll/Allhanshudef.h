#include  "pch.h"

//other


//mainhanshu.cpp=============================================================================================================
void Plant_plants(unsigned int x, unsigned int y, unsigned int kind);//种植植物
void CreateConsole();//创建一个控制台
void PlantRow(int y, int kind);
void Plant_Plants();
void menu();
DWORD WINAPI maingames(LPVOID lpParam);

//gongnenghanshu.cpp=========================================================================================================
void error();//
LPVOID read_addr_chain(LPVOID addr, DWORD Pid);//读取阳光真实地址
int  write_sun(DWORD dPid, LPVOID lpBaseAddress);//写入阳光
void AddresToLittleendian(DWORD address, BYTE* chucun);//将16进制地址转化为小端序储存
void Write_code(DWORD address, DWORD size_of_data, BYTE* data);//写入替换代码到原地址

void Change_Sun();//改阳光的主函数
void Instant_Kill_Plantzombies();//秒杀僵尸

void Plant_no_cooldown();//植物无冷却

void No_planting_limit();//植物种植无限制

DWORD_PTR Create_executable_memory(DWORD size_);//创建可执行代码区域

void Release_all_zombies();//僵尸全员出动

void WritecodeToMemry(void* address, DWORD size_of_num, BYTE* zhili);//写入字节码到内存

void* HookToNewMemory(DWORD_PTR Old_Address, DWORD size_of_OldZhili, BYTE* NewZhili, DWORD size_of_NewZhili/*作用指令大小，不包括跳转指令*/, BYTE* OldZhili);
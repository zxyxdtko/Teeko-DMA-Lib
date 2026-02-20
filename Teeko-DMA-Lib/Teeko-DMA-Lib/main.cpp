#include <iostream>
#include "Teeko-DMA/DMA.hpp"

auto main() -> int
{
    if (!g_Dma.Initialize(true, false)) {
        std::cout << "[-] Failed to initialize DMA!" << std::endl;
        system("pause");
        return -1;
    }

    std::cout << "[+] DMA initialized successfully!" << std::endl;

    if (!g_Dma.Attach("svchost.exe"))
    {
        std::cout << "[-] Failed to attach to destiny2.exe" << std::endl;
        system("pause");
        return -2;
    }

    // 3. Initialize Keyboard Support (poll every 10ms)
    if (!g_Dma.InitKeyboard(10))
    {
        std::cout << "[-] Failed to initialize keyboard" << std::endl;
    }

    // Queue a scan for a specific registry function example
    g_Dma.QueueModuleScan("svchost.exe", "RegQueryDword", "40 53 48 83 EC ? 49 8B D8");

    // Execute all queued scans
    g_Dma.ExecuteModuleScans();

    const std::vector<std::string> scanNames = {
        "RegQueryDword",
    };

    for (const auto& name : scanNames)
    {
        std::cout << "[+] " << name << ": 0x" << std::hex << g_Dma.GetScanResult(name) << std::dec << "\n";
    }

    std::cout << "[+] Test key polling... (W, A, and D)" << std::endl;
    while (true)
    {
        // Example usage of keyboard functions
        if (g_Dma.IsKeyPressed('W')) std::cout << "[+] W key pressed" << std::endl;
        if (g_Dma.IsKeyDown('A')) std::cout << "[+] A key pressed" << std::endl;
        if (g_Dma.IsKeyReleased('D')) std::cout << "[+] D key released" << std::endl;
    }

    system("pause");
    return 0;
}
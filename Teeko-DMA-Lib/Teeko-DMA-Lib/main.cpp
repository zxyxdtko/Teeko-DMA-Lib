#include <iostream>
#include "Teeko-DMA/DMA.hpp"

auto main() -> int
{
    auto& dma = _DMA::Get();

    if (!dma.Initialize(true, true)) {
        std::cout << "[-] Failed to initialize DMA!" << std::endl;
        system("pause");
        return -1;
    }

    std::cout << "[+] DMA initialized successfully!" << std::endl;

    if (!dma.Attach("svchost.exe"))
    {
        std::cout << "[-] Failed to attach to svchost.exe" << std::endl;
        system("pause");
        return -2;
    }

    // 3. Initialize Keyboard Support (poll every 10ms)
    if (!dma.InitKeyboard(10, true))
    {
        std::cout << "[-] Failed to initialize keyboard" << std::endl;
    }

    // Queue a scan for a specific registry function example
    dma.QueueModuleScan("svchost.exe", "RegQueryDword", "40 53 48 83 EC ? 49 8B D8");

    // Execute all queued scans
    dma.ExecuteModuleScans();

    const std::vector<std::string> scanNames = {
        "RegQueryDword",
    };

    for (const auto& name : scanNames)
    {
        std::cout << "[+] " << name << ": 0x" << std::hex << dma.GetScanResult(name) << std::dec << "\n";
    }

    std::cout << "[+] Test key polling... (W, A, and D)" << std::endl;
    while (true)
    {
        // Example usage of keyboard functions
        if (dma.IsKeyPressed('W')) std::cout << "[+] W key pressed" << std::endl;
        if (dma.IsKeyDown('A')) std::cout << "[+] A key held" << std::endl;
        if (dma.IsKeyReleased('D')) std::cout << "[+] D key released" << std::endl;
    }

    system("pause");
    return 0;
}
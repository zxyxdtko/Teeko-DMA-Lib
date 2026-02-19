#include <iostream>
#include "Teeko-DMA/DMA.hpp"

int main()
{
    if (!g_Dma.Initialize()) {
        std::cout << "[-] Failed to initialize DMA!" << std::endl;
        system("pause");
        return -1;
    }

    std::cout << "DMA initialized successfully!" << std::endl;

    if (!g_Dma.Attach("destiny2.exe"))
    {
        std::cout << "[-] Failed to attach to destiny2.exe" << std::endl;
    }

    system("pause");
    return 0;
}
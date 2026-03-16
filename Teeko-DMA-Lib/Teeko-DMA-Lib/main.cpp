#include <iostream>
#include <thread>
#include <chrono>
#include "Teeko-DMA/DMA.hpp"

auto main() -> int
{
    auto& dma = _DMA::Get();

    // 1. Initialize DMA with full debug logging enabled
    if (!dma.Initialize(true, true)) {
        std::cout << "[-] Failed to initialize DMA!" << std::endl;
        system("pause");
        return -1;
    }

    // 2. Attach to a system process
    if (!dma.Attach("svchost.exe"))
    {
        std::cout << "[-] Failed to attach to svchost.exe" << std::endl;
        system("pause");
        return -2;
    }

    // 3. Initialize Keyboard Support (poll every 10ms, debug ON)
    // This locates gafAsyncKeyState in win32kbase.sys
    if (!dma.InitKeyboard(10, true))
    {
        std::cout << "[-] Failed to initialize keyboard" << std::endl;
    }

    // 4. Initialize Xbox Gamepad Support (poll every 4ms, debug ON)
    // This locates the static context array in xboxgip.sys
    if (!dma.InitGamepad(4, true))
    {
        std::cout << "[-] Failed to initialize Xbox Gamepad" << std::endl;
    }

    std::cout << "\n[+] Polling started. Only active inputs will be printed.\n" << std::endl;

    while (true)
    {
        // --- Keyboard Polling ---
        // Checks the global bitmap for the specified virtual keys
        if (dma.IsKeyDown('W')) std::cout << "[KEY] W is held" << std::endl;
        if (dma.IsKeyDown('A')) std::cout << "[KEY] A is held" << std::endl;
        if (dma.IsKeyDown('S')) std::cout << "[KEY] S is held" << std::endl;
        if (dma.IsKeyDown('D')) std::cout << "[KEY] D is held" << std::endl;

        // --- Gamepad Polling ---
        // Checks the translated hardware bitmask for specific buttons
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_A))  std::cout << "[GPAD] A pressed" << std::endl;
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_B))  std::cout << "[GPAD] B pressed" << std::endl;
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_X))  std::cout << "[GPAD] X pressed" << std::endl;
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_Y))  std::cout << "[GPAD] Y pressed" << std::endl;

        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_LEFT_SHOULDER))  std::cout << "[GPAD] LB pressed" << std::endl;
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_RIGHT_SHOULDER)) std::cout << "[GPAD] RB pressed" << std::endl;

        // Fetch analog state for sticks and triggers
        GamepadState state = dma.GetGamepadState();
        if (state.leftTrigger > 10)  std::cout << "[GPAD] LT Depth: " << (int)state.leftTrigger << std::endl;
        if (state.rightTrigger > 10) std::cout << "[GPAD] RT Depth: " << (int)state.rightTrigger << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

#define MAX_CALLBACKS       500
#define DRIVER_NAME         L"\\\\.\\CallbackEnum"
#define IOCTL_ENUM_PROC_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

ULONG proc_cb[MAX_CALLBACKS] = { 0 };
SIZE_T proc_cb_cnt = 0;

namespace callbackEnum {
    namespace ioctl_codes {
        constexpr ULONG processCallbackEnum = IOCTL_ENUM_PROC_CB;
    }

    struct REQUEST {
        ULONG buffer[MAX_CALLBACKS];
        SIZE_T count;
    };

    bool enumProccessCallbacks(HANDLE hDriver) {
        REQUEST recv_req = {};

        bool status = DeviceIoControl(hDriver, ioctl_codes::processCallbackEnum, /*input : none*/&recv_req, sizeof(recv_req), &recv_req, sizeof(recv_req), nullptr, nullptr);

        if (!status) return false;

        SIZE_T to_cpy = (recv_req.count > MAX_CALLBACKS) ? MAX_CALLBACKS : recv_req.count;
        memcpy_s(proc_cb, sizeof(proc_cb), recv_req.buffer, to_cpy * sizeof(ULONG));
        proc_cb_cnt = recv_req.count;

        return proc_cb_cnt > 0;
    }
}

int main() {

    const HANDLE enum_drv = CreateFile(DRIVER_NAME, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (enum_drv == INVALID_HANDLE_VALUE) {
        std::cout << "Erreur du chargement du driver.\n";
        std::cin.get();
        return 1;
    }


    if (callbackEnum::enumProccessCallbacks(enum_drv)) {
        std::cout << "Process callbacks : " << proc_cb_cnt << "\n";
        for (size_t i = 0; i < proc_cb_cnt; ++i)
            std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
    }
    else
    {
        std::cerr << "IOCTL failed (" << GetLastError() << ").\n";
    }


    return 0;
}
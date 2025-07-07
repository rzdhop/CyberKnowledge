#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

#define MAX_CALLBACKS       500
#define DRIVER_NAME         L"\\\\.\\CallbackEnum"

#define IOCTL_ENUM_PROC_CB	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_THRD_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x502, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_LIMG_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x503, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_CMRG_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_PSOB_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x505, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_THOB_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x506, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_DKOB_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x507, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

ULONGLONG proc_cb[MAX_CALLBACKS] = { 0 };
SIZE_T proc_cb_cnt = 0;

namespace callbackEnum {
    namespace ioctl_codes {
        constexpr ULONG processCallbackEnum = IOCTL_ENUM_PROC_CB;
        constexpr ULONG threadCallbackEnum = IOCTL_ENUM_THRD_CB;
        constexpr ULONG limagesCallbackEnum = IOCTL_ENUM_LIMG_CB;
        constexpr ULONG cmregsCallbackEnum = IOCTL_ENUM_CMRG_CB;
        constexpr ULONG psobCallbackEnum = IOCTL_ENUM_PSOB_CB;
        constexpr ULONG thobCallbackEnum = IOCTL_ENUM_THOB_CB;
        constexpr ULONG dkobCallbackEnum = IOCTL_ENUM_DKOB_CB;
    }

    struct REQUEST {
        ULONG64 buffer[MAX_CALLBACKS];
        SIZE_T count;
    };

    bool do_enumCallback(HANDLE hDriver, ULONG callbackType) {
        REQUEST recv_req = {};
        DWORD bytes = 0;

        bool status = DeviceIoControl(hDriver, callbackType, /*input : none*/&recv_req, sizeof(recv_req), &recv_req, sizeof(recv_req), &bytes, nullptr);

        if (!status) return false;

        SIZE_T to_cpy = (recv_req.count > MAX_CALLBACKS) ? MAX_CALLBACKS : recv_req.count;
        memcpy_s(proc_cb, sizeof(proc_cb), recv_req.buffer, to_cpy * sizeof(ULONGLONG));
        proc_cb_cnt = recv_req.count;

        return proc_cb_cnt > 0;
    }

}

int main() {
    int choice;
    std::cout << "Récupération du handle du driver\n";
    const HANDLE enum_drv = CreateFile(DRIVER_NAME, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (enum_drv == INVALID_HANDLE_VALUE) {
        std::cout << "Erreur du chargement du driver.\n";
        return 1;
    }
    std::cout << "Handle du Driver récupéré avec succès!\n";
    
    bool loop = true;
    while (loop) {
        printf("+--- rzdhop's Enumerator ---+\n");
        printf("|                           |\n");
        printf("|    1) Processes           |\n");
        printf("|    2) Threads             |\n");
        printf("|    3) LoadImages          |\n");
        printf("|    4) Registes (CmRegs)   |\n");
        printf("|    5) Objects (Process)   |\n");
        printf("|    6) Objects (Threads)   |\n");
        printf("|    7) Objects (DesktopObj)|\n");
        printf("|                           |\n");
        printf("|    0) Exit                |\n");
        printf("|                           |\n");
        printf("+-- Choice: ");
        std::cin >> choice;

        switch (choice) {
        case 1:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::processCallbackEnum)) {
                std::cout << "Process callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 2:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::threadCallbackEnum)) {
                std::cout << "Threads callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 3:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::limagesCallbackEnum)) {
                std::cout << "Load images callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 4:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::cmregsCallbackEnum)) {
                std::cout << "Load registers callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 5:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::psobCallbackEnum)) {
                std::cout << "Load Process objects callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 6:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::thobCallbackEnum)) {
                std::cout << "Load Thread objects callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 7:
            if (callbackEnum::do_enumCallback(enum_drv, callbackEnum::ioctl_codes::dkobCallbackEnum)) {
                std::cout << "Load Desktop objects callbacks : " << proc_cb_cnt << "\n";
                for (size_t i = 0; i < proc_cb_cnt; ++i)
                    std::cout << "  [" << i << "] 0x" << std::hex << proc_cb[i] << std::dec << '\n';
            }
            else std::cout << "IOCTL failed (" << GetLastError() << ").\n";
            break;
        case 0:
            printf("\n[-] Bye !");
            loop = false;
            break;
        default:
            printf("Unknown choice!\n");
            break;
        }
    }

    std::cout << "Appuyez sur Entrée pour quitter...";
    std::cin.get();
    return 0;
}
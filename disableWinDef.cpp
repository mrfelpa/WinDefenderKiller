#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory> 
#include <stdexcept> 
#include <windows.h>
#include <sddl.h>  
#include <winreg.h> 

using namespace std;

namespace DefenderSettings {
    const wchar_t* const PolicyKeyPath = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    const wchar_t* const RealTimeProtectionKeyPath = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
    const wchar_t* const DisableAntiSpywareValueName = L"DisableAntiSpyware";
    const wchar_t* const DisableRealtimeMonitoringValueName = L"DisableRealtimeMonitoring";
    const wchar_t* const DisableBehaviorMonitoringValueName = L"DisableBehaviorMonitoring";
    const wchar_t* const DisableScanOnRealtimeEnableValueName = L"DisableScanOnRealtimeEnable";
    const wchar_t* const DisableOnAccessProtectionValueName = L"DisableOnAccessProtection";
    const wchar_t* const DisableIOAVProtectionValueName = L"DisableIOAVProtection";
    const DWORD DisableValue = 1;  // Representing the 'disable' state. Using DWORD for registry consistency.
}

std::string getErrorMessage(DWORD errorCode) {
    LPWSTR buffer = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buffer,
        0,
        nullptr);

    if (buffer) {
        std::wstring message(buffer);
        LocalFree(buffer); // Free the allocated buffer
        std::string result(message.begin(), message.end());  // Convert wstring to string
        return result;
    } else {
        std::ostringstream oss;
        oss << "Error code: 0x" << std::hex << std::setw(8) << std::setfill('0') << errorCode;
        return oss.str();
    }
}


class RegKey {
private:
    HKEY handle;

public:
    RegKey(HKEY key) : handle(key) {}
    ~RegKey() {
        if (handle != nullptr) {
            RegCloseKey(handle);
        }
    }

    HKEY get() const { return handle; }
    HKEY* getAddress() { return &handle; } // To pass the address for functions requiring HKEY*

    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    RegKey(RegKey&&) = delete;
    RegKey& operator=(RegKey&&) = delete;
};


bool isUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = nullptr;

    // Convert the string representation of the Administrators SID to a SID structure.
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &administratorsGroup)) {
        std::cerr << "Error converting Administrators SID: " << getErrorMessage(GetLastError()) << std::endl;
        return false;
    }

    std::unique_ptr<void, decltype(&LocalFree)> sidDeleter(administratorsGroup, LocalFree);  //Use LocalFree to free the SID

    if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
        std::cerr << "Error checking token membership: " << getErrorMessage(GetLastError()) << std::endl;
        return false;
    }

    return isAdmin != FALSE;
}

bool setRegistryValue(HKEY key, const wchar_t* valueName, DWORD value) {
    LONG result = RegSetValueExW(key, valueName, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
    if (result != ERROR_SUCCESS) {
        std::cerr << "Error setting registry value '" << valueName << "': " << getErrorMessage(result) << std::endl;
        return false;
    }
    return true;
}


bool createRegistryKey(HKEY parentKey, const wchar_t* subKeyPath, RegKey& newKey) {
    HKEY hKey = nullptr;
    DWORD disposition;  // To check if the key was created or already exists.

    LONG result = RegCreateKeyExW(parentKey, subKeyPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKey, &disposition);

    if (result != ERROR_SUCCESS) {
        std::cerr << "Error creating registry key '" << subKeyPath << "': " << getErrorMessage(result) << std::endl;
        return false;
    }

    newKey = RegKey(hKey); // Take ownership of the key.
    return true;
}

bool openRegistryKey(HKEY parentKey, const wchar_t* subKeyPath, RegKey& openedKey) {
    HKEY hKey = nullptr;

    LONG result = RegOpenKeyExW(parentKey, subKeyPath, 0, KEY_ALL_ACCESS, &hKey);

    if (result != ERROR_SUCCESS) {
        std::cerr << "Error opening registry key '" << subKeyPath << "': " << getErrorMessage(result) << std::endl;
        return false;
    }

    openedKey = RegKey(hKey); // Take ownership of the key.
    return true;
}

int main() {
    if (!isUserAdmin()) {
        cerr << "Error: This program must be run as an administrator." << endl;
        return 1; // Indicate an error.
    }

    try {

        RegKey policyKey;
        if (!openRegistryKey(HKEY_LOCAL_MACHINE, DefenderSettings::PolicyKeyPath, policyKey)) {
            cerr << "Attempting to create the key as it may not exist..." << endl;
             if (!createRegistryKey(HKEY_LOCAL_MACHINE, DefenderSettings::PolicyKeyPath, policyKey)) {
                cerr << "Failed to open or create Windows Defender policy key." << endl;
                return 1;
             }

        }

        if (!setRegistryValue(policyKey.get(), DefenderSettings::DisableAntiSpywareValueName, DefenderSettings::DisableValue)) {
            cerr << "Failed to set DisableAntiSpyware value." << endl;
            return 1;
        }

        RegKey realTimeProtectionKey;

        if (!openRegistryKey(policyKey.get(), L"Real-Time Protection", realTimeProtectionKey))
        {
            cout << "Real Time Protection Key does not exist, creating" << endl;
           if (!createRegistryKey(policyKey.get(), L"Real-Time Protection", realTimeProtectionKey)) {
                cerr << "Failed to create Real-Time Protection key." << endl;
                return 1;
           }
        }


        if (!setRegistryValue(realTimeProtectionKey.get(), DefenderSettings::DisableRealtimeMonitoringValueName, DefenderSettings::DisableValue) ||
            !setRegistryValue(realTimeProtectionKey.get(), DefenderSettings::DisableBehaviorMonitoringValueName, DefenderSettings::DisableValue) ||
            !setRegistryValue(realTimeProtectionKey.get(), DefenderSettings::DisableScanOnRealtimeEnableValueName, DefenderSettings::DisableValue) ||
            !setRegistryValue(realTimeProtectionKey.get(), DefenderSettings::DisableOnAccessProtectionValueName, DefenderSettings::DisableValue) ||
            !setRegistryValue(realTimeProtectionKey.get(), DefenderSettings::DisableIOAVProtectionValueName, DefenderSettings::DisableValue)) {
            cerr << "Failed to set one or more Real-Time Protection values." << endl;
            return 1;
        }

        cout << "Windows Defender settings have been modified successfully." << endl;
        cout << "Please restart your computer for the changes to take effect." << endl;

        cout << "Press Enter to exit." << endl;
        getchar();

        return 0; 

    } catch (const std::exception& e) {
        cerr << "An unexpected error occurred: " << e.what() << endl;
        return 1; 
    } catch (...) {
        cerr << "An unknown error occurred." << endl;
        return 1; 
    }
}

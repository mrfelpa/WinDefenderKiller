#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <stdexcept> 
#include <string>   
#include <memory>   

const wchar_t* REG_PATH = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
const wchar_t* REG_VALUE_NAME = L"DisableAntiSpyware";
const wchar_t* REG_SUBKEY_TO_DELETE = L"Real-Time Protection";

const int ERROR_ELEVATION_REQUIRED = -1;
const int ERROR_REGISTRY_OPERATION_FAILED = -2;
const int ERROR_ALLOCATION_FAILED = -3;
const int ERROR_CHECK_TOKEN_FAILED = -4;

std::wstring GetErrorMessage(DWORD errorCode) {
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
        LocalFree(buffer);
        return message;
    } else {
        return L"Unknown error";
    }
}


// Secure Implementation of isUserAdmin, using RAII for resource management.
bool isUserAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = nullptr;

    try {
        // Use AllocateAndInitializeSid to create the SID
        if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
            DWORD error = GetLastError();
            std::wcerr << L"AllocateAndInitializeSid failed: " << GetErrorMessage(error) << std::endl;
            throw std::runtime_error("Failed to allocate SID for administrators group");
        }

        std::unique_ptr<void, decltype(&FreeSid)> administratorsGroupDeleter(AdministratorsGroup, FreeSid);

        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
            DWORD error = GetLastError();
            std::wcerr << L"CheckTokenMembership failed: " << GetErrorMessage(error) << std::endl;
            throw std::runtime_error("Failed to check token membership");
        }

        return isAdmin != FALSE;

    } catch (const std::runtime_error& e) {
        std::cerr << "Error in isUserAdmin: " << e.what() << std::endl;
        return false;
    }
}


// Securely enable Windows Defender via registry with error handling, input validation, and RAII.
int main(int argc, char* argv[]) {
    if (!isUserAdmin()) {
        std::cerr << "Error: Please run this program as an administrator." << std::endl;
        return ERROR_ELEVATION_REQUIRED;
    }

    HKEY key = nullptr;
    DWORD enable = 0; // Set to 0 to enable Windows Defender

    try {
        // Open the registry key with only necessary permissions (KEY_SET_VALUE | KEY_WOW64_64KEY)
        LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PATH, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key);
        if (res != ERROR_SUCCESS) {
            DWORD error = GetLastError();
            std::wcerr << L"RegOpenKeyEx failed: " << GetErrorMessage(error) << std::endl;
            throw std::runtime_error("Failed to open registry key.");
        }
         // RAII to ensure the key is closed.
        std::unique_ptr<HKEY, decltype(&RegCloseKey)> keyCloser(key, RegCloseKey);

        // Set the "DisableAntiSpyware" value back to 0 (enabled)
        res = RegSetValueExW(key, REG_VALUE_NAME, 0, REG_DWORD, (const BYTE*)&enable, sizeof(enable));
        if (res != ERROR_SUCCESS) {
            DWORD error = GetLastError();
            std::wcerr << L"RegSetValueEx failed: " << GetErrorMessage(error) << std::endl;
            throw std::runtime_error("Failed to set registry value.");
        }

        HKEY subKeyToDelete = nullptr;
        res = RegOpenKeyExW(key, REG_SUBKEY_TO_DELETE, 0, DELETE, &subKeyToDelete); // Open with DELETE access.

        if (res == ERROR_SUCCESS) {
            //RAII for subkey deletion.
            std::unique_ptr<HKEY, decltype(&RegCloseKey)> subKeyCloser(subKeyToDelete, RegCloseKey);

            res = RegDeleteTreeW(key, REG_SUBKEY_TO_DELETE);  //Recursively delete the entire subkey structure.
            if (res != ERROR_SUCCESS) {
                DWORD error = GetLastError();
                std::wcerr << L"RegDeleteTree failed: " << GetErrorMessage(error) << std::endl;
                std::cerr << "Warning: Failed to delete registry subkey.  This might require manual intervention." << std::endl;
            } else {
                std::cout << "Successfully deleted " << REG_SUBKEY_TO_DELETE << std::endl;
            }
        } else if (res == ERROR_FILE_NOT_FOUND) {
            std::cout << "Subkey " << REG_SUBKEY_TO_DELETE << " not found.  Skipping deletion." << std::endl;
        } else {
            DWORD error = GetLastError();
            std::wcerr << L"RegOpenKeyEx (for deletion) failed: " << GetErrorMessage(error) << std::endl;
            std::cerr << "Warning: Could not open registry subkey for deletion." << std::endl;
        }

        std::cout << "Windows Defender has been enabled." << std::endl;
        std::cout << "Please restart your computer for the changes to take effect." << std::endl;

    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return ERROR_REGISTRY_OPERATION_FAILED;
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return -99; 
    }

    return 0;
}

//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <ioctl_private.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <SetupAPI.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

HANDLE
bfm_ioctl_open()
{
    HANDLE hDevInfo;
    SP_INTERFACE_DEVICE_DETAIL_DATA *deviceDetailData = nullptr;

    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

    SP_INTERFACE_DEVICE_DATA ifInfo;
    ifInfo.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

    hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_builder, 0, 0, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return hDevInfo;
    }

    if (SetupDiEnumDeviceInfo(hDevInfo, 0, &devInfo) == false) {
        return INVALID_HANDLE_VALUE;
    }

    if (SetupDiEnumDeviceInterfaces(hDevInfo, &devInfo, &(GUID_DEVINTERFACE_builder), 0, &ifInfo) == false) {
        return INVALID_HANDLE_VALUE;
    }

    DWORD requiredSize = 0;

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &ifInfo, NULL, 0, &requiredSize, NULL) == TRUE) {
        return INVALID_HANDLE_VALUE;
    }

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return INVALID_HANDLE_VALUE;
    }

    deviceDetailData = static_cast<SP_INTERFACE_DEVICE_DETAIL_DATA *>(malloc(requiredSize));

    if (deviceDetailData == nullptr) {
        return INVALID_HANDLE_VALUE;
    }

    auto ___ = gsl::finally([&]
    { free(deviceDetailData); });

    deviceDetailData->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &ifInfo, deviceDetailData, requiredSize, NULL, NULL) == false) {
        return INVALID_HANDLE_VALUE;
    }

    return CreateFile(deviceDetailData->DevicePath,
                      GENERIC_READ | GENERIC_WRITE,
                      0,
                      NULL,
                      CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
}

int64_t
bfm_read_write_ioctl(HANDLE fd, DWORD request, void *data, DWORD size)
{
    DWORD bytes = 0;
    if (!DeviceIoControl(fd, request, data, size, data, size, &bytes, NULL)) {
        return BF_IOCTL_FAILURE;
    }

    return 0;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
    if ((fd = bfm_ioctl_open()) == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("failed to open to builder");
    }
}

ioctl_private::~ioctl_private()
{ CloseHandle(fd); }

void
ioctl_private::call_ioctl_create_from_elf(create_from_elf_args &args)
{
    if (bfm_read_write_ioctl(fd, IOCTL_CREATE_FROM_ELF_CMD, &args, sizeof(create_from_elf_args)) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_FROM_ELF_CMD");
    }
}

void
ioctl_private::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (bfm_read_write_ioctl(fd, IOCTL_DESTROY_CMD, &domainid, sizeof(domainid_t)) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_DESTROY_CMD\n";
    }
}

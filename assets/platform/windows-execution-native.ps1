$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ([IntPtr]::Size -ne 8 -or
    ![string]::Equals([Environment]::SystemDirectory, 'C:\Windows\System32', [StringComparison]::OrdinalIgnoreCase) -or
    ![string]::Equals($PSHOME, 'C:\Windows\System32\WindowsPowerShell\v1.0', [StringComparison]::OrdinalIgnoreCase) -or
    ![string]::Equals([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName,
      'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', [StringComparison]::OrdinalIgnoreCase)) { throw 'bootstrap' }
Import-Module -Name 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1' -ErrorAction Stop
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false, $true)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)
$assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
  [Reflection.AssemblyName]::new('MissionSpec.WindowsExecution'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
$nativeType = $assembly.DefineDynamicModule('Native').DefineType('ExecutionNative', 'Public, Sealed, Abstract')
function Add-Native($name, $dll, $result, [Type[]]$parameters) {
  $method = $nativeType.DefinePInvokeMethod($name, $dll, 'Public, Static, PinvokeImpl',
    [Reflection.CallingConventions]::Standard, $result, $parameters,
    [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
  $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
  $attribute = [Runtime.InteropServices.DllImportAttribute]
  $method.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new(
    $attribute.GetConstructor([Type[]]@([string])), [object[]]@($dll),
    [Reflection.FieldInfo[]]@($attribute.GetField('CharSet'), $attribute.GetField('ExactSpelling'), $attribute.GetField('SetLastError')),
    [object[]]@([Runtime.InteropServices.CharSet]::Unicode, $true, $true)))
}
Add-Native 'CloseHandle' 'kernel32.dll' ([bool]) @([IntPtr])
Add-Native 'GetStdHandle' 'kernel32.dll' ([IntPtr]) @([int])
Add-Native 'GetFileType' 'kernel32.dll' ([uint32]) @([IntPtr])
Add-Native 'GetConsoleMode' 'kernel32.dll' ([bool]) @([IntPtr], [uint32].MakeByRefType())
Add-Native 'ReadConsoleW' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr], [uint32], [uint32].MakeByRefType(), [IntPtr])
Add-Native 'WriteConsoleW' 'kernel32.dll' ([bool]) @([IntPtr], [string], [uint32], [uint32].MakeByRefType(), [IntPtr])
Add-Native 'CreateNamedPipeW' 'kernel32.dll' ([IntPtr]) @([string], [uint32], [uint32], [uint32], [uint32], [uint32], [uint32], [IntPtr])
Add-Native 'GetNamedPipeClientProcessId' 'kernel32.dll' ([bool]) @([IntPtr], [uint32].MakeByRefType())
Add-Native 'ConvertStringSecurityDescriptorToSecurityDescriptorW' 'advapi32.dll' ([bool]) @([string], [uint32], [IntPtr].MakeByRefType(), [uint32].MakeByRefType())
Add-Native 'LocalFree' 'kernel32.dll' ([IntPtr]) @([IntPtr])
Add-Native 'CreateFileW' 'kernel32.dll' ([IntPtr]) @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])
Add-Native 'GetFinalPathNameByHandleW' 'kernel32.dll' ([uint32]) @([IntPtr], [Text.StringBuilder], [uint32], [uint32])
Add-Native 'GetFileInformationByHandle' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr])
Add-Native 'GetFileInformationByHandleEx' 'kernel32.dll' ([bool]) @([IntPtr], [int], [IntPtr], [uint32])
Add-Native 'GetDriveTypeW' 'kernel32.dll' ([uint32]) @([string])
Add-Native 'QueryDosDeviceW' 'kernel32.dll' ([uint32]) @([string], [Text.StringBuilder], [uint32])
Add-Native 'CreateJobObjectW' 'kernel32.dll' ([IntPtr]) @([IntPtr], [string])
Add-Native 'SetInformationJobObject' 'kernel32.dll' ([bool]) @([IntPtr], [int], [IntPtr], [uint32])
Add-Native 'QueryInformationJobObject' 'kernel32.dll' ([bool]) @([IntPtr], [int], [IntPtr], [uint32], [IntPtr])
Add-Native 'TerminateJobObject' 'kernel32.dll' ([bool]) @([IntPtr], [uint32])
Add-Native 'IsProcessInJob' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr], [bool].MakeByRefType())
Add-Native 'InitializeProcThreadAttributeList' 'kernel32.dll' ([bool]) @([IntPtr], [int], [uint32], [IntPtr].MakeByRefType())
Add-Native 'UpdateProcThreadAttribute' 'kernel32.dll' ([bool]) @([IntPtr], [uint32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr])
Add-Native 'DeleteProcThreadAttributeList' 'kernel32.dll' ([void]) @([IntPtr])
Add-Native 'CreateProcessW' 'kernel32.dll' ([bool]) @([string], [Text.StringBuilder], [IntPtr], [IntPtr], [bool], [uint32], [IntPtr], [string], [IntPtr], [IntPtr])
Add-Native 'CreatePipe' 'kernel32.dll' ([bool]) @([IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr], [uint32])
Add-Native 'SetHandleInformation' 'kernel32.dll' ([bool]) @([IntPtr], [uint32], [uint32])
Add-Native 'PeekNamedPipe' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr], [uint32], [IntPtr], [uint32].MakeByRefType(), [IntPtr])
Add-Native 'ReadFile' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr], [uint32], [uint32].MakeByRefType(), [IntPtr])
Add-Native 'WriteFile' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr], [uint32], [uint32].MakeByRefType(), [IntPtr])
Add-Native 'OpenProcess' 'kernel32.dll' ([IntPtr]) @([uint32], [bool], [uint32])
Add-Native 'ResumeThread' 'kernel32.dll' ([uint32]) @([IntPtr])
Add-Native 'WaitForSingleObject' 'kernel32.dll' ([uint32]) @([IntPtr], [uint32])
Add-Native 'GetExitCodeProcess' 'kernel32.dll' ([bool]) @([IntPtr], [uint32].MakeByRefType())
Add-Native 'GetProcessTimes' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr])
Add-Native 'CreateEventW' 'kernel32.dll' ([IntPtr]) @([IntPtr], [bool], [bool], [string])
Add-Native 'SetEvent' 'kernel32.dll' ([bool]) @([IntPtr])
Add-Native 'WaitForMultipleObjects' 'kernel32.dll' ([uint32]) @([uint32], [IntPtr], [bool], [uint32])
Add-Native 'GetCurrentProcess' 'kernel32.dll' ([IntPtr]) @()
Add-Native 'TerminateProcess' 'kernel32.dll' ([bool]) @([IntPtr], [uint32])
$native = $nativeType.CreateType()
$allocations = [Collections.Generic.List[IntPtr]]::new()
$handles = [Collections.Generic.List[IntPtr]]::new()
function Memory([int]$length) {
  $p = [Runtime.InteropServices.Marshal]::AllocHGlobal($length)
  $allocations.Add($p)
  [Runtime.InteropServices.Marshal]::Copy([byte[]]::new($length), 0, $p, $length)
  return $p
}
function Own([IntPtr]$h) {
  if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr](-1)) { throw $phase }
  $handles.Add($h)
  return $h
}
function Close-Owned([IntPtr]$h) {
  if (!$handles.Remove($h) -or !$native::CloseHandle($h)) { throw 'close' }
}
function Release-Native {
  $failed = $false
  for ($i = $handles.Count - 1; $i -ge 0; $i--) {
    if (!$native::CloseHandle($handles[$i])) { $failed = $true }
  }
  foreach ($p in $allocations) { [Runtime.InteropServices.Marshal]::FreeHGlobal($p) }
  if ($failed) { throw 'close' }
}
function Open-Parent([uint32]$processId) {
  $parent = Own ($native::OpenProcess(0x101000, $false, $processId))
  $parentTimes = Memory 32
  $selfTimes = Memory 32
  foreach ($entry in @(@($parent, $parentTimes), @($native::GetCurrentProcess(), $selfTimes))) {
    if (!$native::GetProcessTimes($entry[0], $entry[1], [IntPtr]::Add($entry[1], 8),
        [IntPtr]::Add($entry[1], 16), [IntPtr]::Add($entry[1], 24))) { throw 'input' }
  }
  # A reused PID belongs to a process born after this helper, not its caller.
  if ([Runtime.InteropServices.Marshal]::ReadInt64($parentTimes) -ge
      [Runtime.InteropServices.Marshal]::ReadInt64($selfTimes) -or
      $native::WaitForSingleObject($parent, 0) -ne 258) { throw 'input' }
  return $parent
}
function Start-ParentWatch([IntPtr]$parent, [uint32]$timeout) {
  $stop = Own ($native::CreateEventW([IntPtr]::Zero, $true, $false, $null))
  $waitHandles = Memory 16
  [Runtime.InteropServices.Marshal]::WriteIntPtr($waitHandles, 0, $parent)
  [Runtime.InteropServices.Marshal]::WriteIntPtr($waitHandles, 8, $stop)
  $watchType = $assembly.GetDynamicModule('Native').DefineType('ConsoleParentWatch', 'Public, Sealed, Abstract')
  $handleField = $watchType.DefineField('Handles', [IntPtr], 'Public, Static')
  $timeoutField = $watchType.DefineField('Timeout', [uint32], 'Public, Static')
  $method = $watchType.DefineMethod('Wait', 'Public, Static', [void], [Type[]]@())
  $il = $method.GetILGenerator()
  $done = $il.DefineLabel()
  $il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_2)
  $il.Emit([Reflection.Emit.OpCodes]::Ldsfld, $handleField)
  $il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_0)
  $il.Emit([Reflection.Emit.OpCodes]::Ldsfld, $timeoutField)
  $il.Emit([Reflection.Emit.OpCodes]::Call, $native.GetMethod('WaitForMultipleObjects'))
  $il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_1)
  $il.Emit([Reflection.Emit.OpCodes]::Beq, $done)
  $il.Emit([Reflection.Emit.OpCodes]::Call, $native.GetMethod('GetCurrentProcess'))
  $il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_1)
  $il.Emit([Reflection.Emit.OpCodes]::Call, $native.GetMethod('TerminateProcess'))
  $il.Emit([Reflection.Emit.OpCodes]::Pop)
  $il.MarkLabel($done)
  $il.Emit([Reflection.Emit.OpCodes]::Ret)
  $watch = $watchType.CreateType()
  $watch.GetField('Handles').SetValue($null, $waitHandles)
  $watch.GetField('Timeout').SetValue($null, $timeout)
  $thread = [Threading.Thread]::new([Threading.ThreadStart][Delegate]::CreateDelegate([Threading.ThreadStart], $watch.GetMethod('Wait')))
  $thread.IsBackground = $true
  $thread.Start()
  return @{ stop=$stop; thread=$thread }
}
function Stop-ParentWatch($watch) {
  if (!$native::SetEvent($watch.stop) -or !$watch.thread.Join(1000)) {
    # Never free memory or close a handle still being waited on.
    [void]$native::TerminateProcess($native::GetCurrentProcess(), 1)
    throw 'close'
  }
}
function Quoted-Argument([string]$value) {
  if ($value.Contains([string][char]0)) { throw 'input' }
  # Windows CRT quoting: double backslashes only before a quote or the closing quote.
  return '"' + [regex]::Replace([regex]::Replace($value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

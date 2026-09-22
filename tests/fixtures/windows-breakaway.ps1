param([string]$Program, [string]$WorkingDirectory)
$phase = 'bootstrap'
$nativeStatus = 0
try {
  . ($PSScriptRoot + '\..\..\assets\platform\windows-execution-native.ps1')
  try {
    if ([string]::IsNullOrEmpty($WorkingDirectory)) { throw 'working-directory' }
    # Capture the P/Invoke error before returning through PowerShell's dynamic binder.
    $probeType = $assembly.GetDynamicModule('Native').DefineType('BreakawayProbe', 'Public, Sealed, Abstract')
    $parameters = [Type[]]@([string], [Text.StringBuilder], [IntPtr], [IntPtr], [bool],
      [uint32], [IntPtr], [string], [IntPtr], [IntPtr], [int].MakeByRefType())
    $method = $probeType.DefineMethod('CreateProcessObserved', 'Public, Static', [bool], $parameters)
    $il = $method.GetILGenerator()
    $createdLocal = $il.DeclareLocal([bool])
    for ($index = 0; $index -lt 10; $index++) { $il.Emit([Reflection.Emit.OpCodes]::Ldarg, [int16]$index) }
    $il.Emit([Reflection.Emit.OpCodes]::Call, $native.GetMethod('CreateProcessW'))
    $il.Emit([Reflection.Emit.OpCodes]::Stloc, $createdLocal)
    $il.Emit([Reflection.Emit.OpCodes]::Ldarg, [int16]10)
    $il.Emit([Reflection.Emit.OpCodes]::Call, [Runtime.InteropServices.Marshal].GetMethod('GetLastWin32Error'))
    $il.Emit([Reflection.Emit.OpCodes]::Stind_I4)
    $il.Emit([Reflection.Emit.OpCodes]::Ldloc, $createdLocal)
    $il.Emit([Reflection.Emit.OpCodes]::Ret)
    $probe = $probeType.CreateType()
    $startup = Memory 104
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 0, 104)
    $info = Memory 24
    $phase = 'control-create'
    $ordinary = [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "process.exit(0)"')
    # PowerShell coerces a null argument for this string parameter to an empty path.
    $created = $probe::CreateProcessObserved($Program, $ordinary, [IntPtr]::Zero, [IntPtr]::Zero, $false,
      0, [IntPtr]::Zero, $WorkingDirectory, $startup, $info, [ref]$nativeStatus)
    if (!$created) { throw 'control-create' }
    $control = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0))
    [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
    $inJob = $false
    $code = [uint32]0
    if (!$native::IsProcessInJob($control, [IntPtr]::Zero, [ref]$inJob) -or !$inJob -or
        $native::WaitForSingleObject($control, 5000) -ne 0 -or
        !$native::GetExitCodeProcess($control, [ref]$code) -or $code -ne 0) { throw 'control-completion' }
    $phase = 'breakaway-create'
    $command = [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "process.exit(0)"')
    $created = $probe::CreateProcessObserved($Program, $command, [IntPtr]::Zero, [IntPtr]::Zero, $false,
      0x01000000, [IntPtr]::Zero, $WorkingDirectory, $startup, $info, [ref]$nativeStatus)
    if ($created) {
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0)))
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
      throw 'breakaway-was-allowed'
    }
    if ($nativeStatus -ne 5) { throw 'unexpected-breakaway-failure' }
  } finally { Release-Native }
  [Console]::Out.Write('breakaway-denied')
} catch {
  [Console]::Out.Write(('WINDOWS_BREAKAWAY_FAILURE:{"phase":"' + $phase + '","line":' + [int]$_.InvocationInfo.ScriptLineNumber + ',"nativeStatus":' + [int]$nativeStatus + '}'))
  exit 1
}

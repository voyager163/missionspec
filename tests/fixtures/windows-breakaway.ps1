param([string]$Program)
$phase = 'bootstrap'
try {
  . ($PSScriptRoot + '\..\..\assets\platform\windows-execution-native.ps1')
  try {
    $startup = Memory 104
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 0, 104)
    $info = Memory 24
    $phase = 'control-create'
    $ordinary = [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "process.exit(0)"')
    if (!$native::CreateProcessW($Program, $ordinary, [IntPtr]::Zero, [IntPtr]::Zero, $false,
        0, [IntPtr]::Zero, $null, $startup, $info)) { throw 'control-create' }
    $control = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0))
    [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
    $inJob = $false
    $code = [uint32]0
    if (!$native::IsProcessInJob($control, [IntPtr]::Zero, [ref]$inJob) -or !$inJob -or
        $native::WaitForSingleObject($control, 5000) -ne 0 -or
        !$native::GetExitCodeProcess($control, [ref]$code) -or $code -ne 0) { throw 'control-completion' }
    $phase = 'breakaway-create'
    $command = [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "process.exit(0)"')
    $created = $native::CreateProcessW($Program, $command, [IntPtr]::Zero, [IntPtr]::Zero, $false,
      0x01000000, [IntPtr]::Zero, $null, $startup, $info)
    if ($created) {
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0)))
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
      throw 'breakaway-was-allowed'
    }
  } finally { Release-Native }
  [Console]::Out.Write('breakaway-denied')
} catch {
  [Console]::Out.Write(('WINDOWS_BREAKAWAY_FAILURE:{"phase":"' + $phase + '","line":' + [int]$_.InvocationInfo.ScriptLineNumber + '}'))
  exit 1
}

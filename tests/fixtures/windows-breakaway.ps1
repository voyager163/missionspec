param([string]$Program)
$phase = 'bootstrap'
try {
  . ($PSScriptRoot + '\..\..\assets\platform\windows-execution-native.ps1')
  try {
    $startup = Memory 104
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 0, 104)
    $info = Memory 24
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
} catch { [Console]::Out.Write('breakaway-test-failed'); exit 1 }

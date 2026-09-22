param([string]$Program, [string]$WorkingDirectory)
$phase = 'bootstrap'
$nativeStatus = 0
try {
  . ($PSScriptRoot + '\..\..\assets\platform\windows-execution-native.ps1')
  try {
    if ([string]::IsNullOrEmpty($WorkingDirectory)) { throw 'working-directory' }
    # A test-only compiled stub captures BOOL and last-error in one managed return.
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public sealed class BreakawayCreation {
  public bool Created;
  public int ErrorCode;
}
public static class BreakawayProbe {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
  private static extern bool CreateProcessW(string application, StringBuilder command,
    IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
    IntPtr environment, string directory, IntPtr startup, IntPtr information);
  public static BreakawayCreation Create(string application, StringBuilder command,
    uint flags, string directory, IntPtr startup, IntPtr information) {
    bool created = CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero,
      false, flags, IntPtr.Zero, directory, startup, information);
    int error = Marshal.GetLastWin32Error();
    return new BreakawayCreation { Created = created, ErrorCode = error };
  }
}
'@
    $startup = Memory 104
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 0, 104)
    $info = Memory 24
    $phase = 'control-create'
    $invalidDirectory = [IO.Path]::Combine($WorkingDirectory, [Guid]::NewGuid().ToString())
    $errorControl = [BreakawayProbe]::Create($Program,
      [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "process.exit(0)"'),
      0, $invalidDirectory, $startup, $info)
    $nativeStatus = $errorControl.ErrorCode
    if ($errorControl.Created) {
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0)))
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
      throw 'invalid-directory-was-accepted'
    }
    if ($nativeStatus -notin @(3, 267)) { throw 'last-error-control' }
    $ordinary = [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "process.exit(0)"')
    # PowerShell coerces a null argument for this string parameter to an empty path.
    $observation = [BreakawayProbe]::Create($Program, $ordinary, 0, $WorkingDirectory, $startup, $info)
    $nativeStatus = $observation.ErrorCode
    if (!$observation.Created) { throw 'control-create' }
    $control = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0))
    [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
    $inJob = $false
    $code = [uint32]0
    if (!$native::IsProcessInJob($control, [IntPtr]::Zero, [ref]$inJob) -or !$inJob -or
        $native::WaitForSingleObject($control, 5000) -ne 0 -or
        !$native::GetExitCodeProcess($control, [ref]$code) -or $code -ne 0) { throw 'control-completion' }
    $phase = 'breakaway-create'
    $command = [Text.StringBuilder]::new((Quoted-Argument $Program) + ' -e "setTimeout(()=>process.exit(0),60000)"')
    $observation = [BreakawayProbe]::Create($Program, $command, 0x01000000, $WorkingDirectory, $startup, $info)
    $nativeStatus = $observation.ErrorCode
    if ($observation.Created) {
      $child = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0))
      [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
      $times = Memory 32
      if (!$native::GetProcessTimes($child, $times, [IntPtr]::Add($times, 8),
          [IntPtr]::Add($times, 16), [IntPtr]::Add($times, 24))) {
        [void]$native::TerminateProcess($child, 1)
        throw 'child-identity'
      }
      $childId = [Runtime.InteropServices.Marshal]::ReadInt32($info, 16)
      $createdAt = [Runtime.InteropServices.Marshal]::ReadInt64($times).ToString([Globalization.CultureInfo]::InvariantCulture)
      $result = '{"state":"created","pid":' + $childId + ',"createdAt":"' + $createdAt + '"}'
      [IO.File]::WriteAllText([IO.Path]::Combine($WorkingDirectory, 'breakaway-child.json'), $result)
    } else {
      if ($nativeStatus -ne 5) { throw 'unexpected-breakaway-failure' }
      $result = '{"state":"denied","nativeStatus":5}'
    }
  } finally { Release-Native }
  [Console]::Out.Write($result)
} catch {
  [Console]::Out.Write(('WINDOWS_BREAKAWAY_FAILURE:{"phase":"' + $phase + '","line":' + [int]$_.InvocationInfo.ScriptLineNumber + ',"nativeStatus":' + [int]$nativeStatus + '}'))
  exit 1
}

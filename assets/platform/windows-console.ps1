param([string]$PipeName, [int]$ParentProcess)
$phase = 'bootstrap'
try {
  . ($PSScriptRoot + '\windows-execution-native.ps1')
  $pipe = $null
  $watch = $null
  $descriptor = [IntPtr]::Zero
  try {
    $phase = 'input'
    if ($PipeName -cnotmatch '^missionspec-console-[a-f0-9]{64}$' -or $ParentProcess -le 0) { throw 'input' }
    $parent = Open-Parent ([uint32]$ParentProcess)
    $watch = Start-ParentWatch $parent 120000
    $phase = 'console'
    $consoleInput = $native::GetStdHandle(-10)
    $consoleOutput = $native::GetStdHandle(-12)
    $inputMode = [uint32]0
    $outputMode = [uint32]0
    if ($native::GetFileType($consoleInput) -ne 2 -or $native::GetFileType($consoleOutput) -ne 2 -or
        !$native::GetConsoleMode($consoleInput, [ref]$inputMode) -or
        !$native::GetConsoleMode($consoleOutput, [ref]$outputMode) -or ($inputMode -band 3) -ne 3) { throw 'console' }
    $phase = 'pipe'
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $length = [uint32]0
    if (!$native::ConvertStringSecurityDescriptorToSecurityDescriptorW(('O:' + $sid + 'D:P(A;;GA;;;' + $sid + ')'),
        1, [ref]$descriptor, [ref]$length)) { throw 'pipe' }
    $sa = Memory 24
    [Runtime.InteropServices.Marshal]::WriteInt32($sa, 0, 24)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($sa, 8, $descriptor)
    # A private local-only first-instance pipe carries display data, never a
    # decision. stdin/stderr remain the actual inherited console handles.
    $pipeHandle = $native::CreateNamedPipeW(('\\.\pipe\' + $PipeName), 0x80003, 8, 1, 0, 65536, 0, $sa)
    if ($pipeHandle -eq [IntPtr](-1)) { throw 'pipe' }
    $safePipe = [Microsoft.Win32.SafeHandles.SafePipeHandle]::new($pipeHandle, $true)
    $pipe = [IO.Pipes.NamedPipeServerStream]::new([IO.Pipes.PipeDirection]::InOut, $false, $false, $safePipe)
    [Console]::Out.WriteLine('{"phase":"ready"}')
    [Console]::Out.Flush()
    $pipe.WaitForConnection()
    $client = [uint32]0
    if (!$native::GetNamedPipeClientProcessId($pipeHandle, [ref]$client) -or $client -ne $ParentProcess -or
        $native::WaitForSingleObject($parent, 0) -ne 258) { throw 'pipe' }
    $reader = [IO.BinaryReader]::new($pipe, [Text.UTF8Encoding]::new($false, $true), $true)
    try {
      $size = $reader.ReadInt32()
      if ($size -le 0 -or $size -gt 6000000) { throw 'input' }
      $bytes = $reader.ReadBytes($size)
      if ($bytes.Length -ne $size) { throw 'input' }
      $request = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    } finally { $reader.Dispose(); $pipe.Dispose(); $pipe = $null }
    $phase = 'input'
    if ([string]$request.challenge -cnotmatch '^confirm [a-f0-9]{32}$' -or
        [string]$request.correlation -cnotmatch '^[a-f0-9]{64}$' -or
        $request.display -isnot [string] -or $request.action -cnotin @('issue', 'revoke')) { throw 'input' }
    $dateStyle = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $deadline = [DateTimeOffset]::ParseExact([string]$request.deadline, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture, $dateStyle)
    $expires = [DateTimeOffset]::ParseExact([string]$request.expires, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture, $dateStyle)
    $start = [DateTimeOffset]::UtcNow
    if ($deadline -le $start -or $deadline -gt $start.AddSeconds(120) -or $expires -le $start) { throw 'input' }
    $phase = 'display'
    $display = "`nLOCAL USER REVIEW - no organization or tamper-proof assurance.`n" + [string]$request.display +
      "`nType exactly `"" + [string]$request.challenge + "`" to confirm this " + [string]$request.action +
      " review; it expires " + [string]$request.expires + ":`n> "
    for ($offset = 0; $offset -lt $display.Length;) {
      $take = [Math]::Min(4096, $display.Length - $offset)
      if ([char]::IsHighSurrogate($display[$offset + $take - 1])) { $take-- }
      if ($take -le 0) { throw 'display' }
      $segment = $display.Substring($offset, $take)
      $written = [uint32]0
      if (!$native::WriteConsoleW($consoleOutput, $segment, $segment.Length, [ref]$written, [IntPtr]::Zero) -or
          $written -eq 0 -or $written -gt $segment.Length) { throw 'display' }
      $offset += $written
    }
    $phase = 'challenge'
    $buffer = Memory 1024
    $read = [uint32]0
    if (!$native::ReadConsoleW($consoleInput, $buffer, 511, [ref]$read, [IntPtr]::Zero) -or $read -eq 0) { throw 'challenge' }
    $answer = [Runtime.InteropServices.Marshal]::PtrToStringUni($buffer, [int]$read)
    $now = [DateTimeOffset]::UtcNow
    $decision = if ($now -lt $start -or $now -ge $deadline -or $now -ge $expires -or
        $native::WaitForSingleObject($parent, 0) -ne 258) { 'cancel' }
      elseif ($answer -ceq ([string]$request.challenge + "`r`n")) { 'accept' }
      else { 'decline' }
    $result = @{ok=$true;decision=$decision;correlation=[string]$request.correlation}
    $phase = 'close'
  } finally {
    if ($null -ne $watch) { Stop-ParentWatch $watch }
    if ($null -ne $pipe) { $pipe.Dispose() }
    if ($descriptor -ne [IntPtr]::Zero) { [void]$native::LocalFree($descriptor) }
    Release-Native
  }
  [Console]::Out.WriteLine(($result | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
} catch {
  [Console]::Out.WriteLine(('{"ok":false,"phase":"' + $phase + '","line":' + [int]$_.InvocationInfo.ScriptLineNumber + '}'))
  exit 1
}

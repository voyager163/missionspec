$phase = 'bootstrap'
$protocolOutput = $null
$transcript = $null
try {
  . ($PSScriptRoot + '\..\..\assets\platform\windows-execution-native.ps1')
  $protocolOutput = [Console]::Out
  $nativeType = $assembly.DefineDynamicModule('ConPty').DefineType('ConPtyNative', 'Public, Sealed, Abstract')
  Add-Native 'CreatePseudoConsole' 'kernel32.dll' ([int]) @([uint32], [IntPtr], [IntPtr], [uint32], [IntPtr].MakeByRefType())
  Add-Native 'ClosePseudoConsole' 'kernel32.dll' ([void]) @([IntPtr])
  Add-Native 'SetStdHandle' 'kernel32.dll' ([bool]) @([int], [IntPtr])
  $conpty = $nativeType.CreateType()
  function Close-ConPtyAsync([IntPtr]$handle) {
    $closerType = $assembly.GetDynamicModule('ConPty').DefineType('ConPtyCloser', 'Public, Sealed, Abstract')
    $field = $closerType.DefineField('Handle', [IntPtr], 'Public, Static')
    $method = $closerType.DefineMethod('Close', 'Public, Static', [void], [Type[]]@())
    $il = $method.GetILGenerator()
    $il.Emit([Reflection.Emit.OpCodes]::Ldsfld, $field)
    $il.Emit([Reflection.Emit.OpCodes]::Call, $conpty.GetMethod('ClosePseudoConsole'))
    $il.Emit([Reflection.Emit.OpCodes]::Ret)
    $type = $closerType.CreateType()
    $type.GetField('Handle').SetValue($null, $handle)
    $thread = [Threading.Thread]::new([Threading.ThreadStart][Delegate]::CreateDelegate([Threading.ThreadStart], $type.GetMethod('Close')))
    $thread.IsBackground = $true
    $thread.Start()
    return $thread
  }
  $console = [IntPtr]::Zero
  $attributes = [IntPtr]::Zero
  $job = [IntPtr]::Zero
  $closer = $null
  $reader = $null
  try {
    $request = [Console]::In.ReadToEnd() | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $phase = 'pipes'
    $inputRead = [IntPtr]::Zero
    $inputWrite = [IntPtr]::Zero
    $outputRead = [IntPtr]::Zero
    $outputWrite = [IntPtr]::Zero
    if (!$native::CreatePipe([ref]$inputRead, [ref]$inputWrite, [IntPtr]::Zero, 0) -or
        !$native::CreatePipe([ref]$outputRead, [ref]$outputWrite, [IntPtr]::Zero, 0)) { throw 'pipes' }
    [void](Own $inputRead); [void](Own $inputWrite); [void](Own $outputRead); [void](Own $outputWrite)
    $phase = 'console'
    $status = $conpty::CreatePseudoConsole([uint32](80 * 65536 + 240), $inputRead, $outputWrite, 0, [ref]$console)
    if ($status -ne 0) { throw 'console' }
    $phase = 'job'
    $job = Own ($native::CreateJobObjectW([IntPtr]::Zero, $null))
    $limits = Memory 144
    [Runtime.InteropServices.Marshal]::WriteInt32($limits, 16, 0x2000)
    if (!$native::SetInformationJobObject($job, 9, $limits, 144)) { throw 'job' }
    $phase = 'attributes'
    $size = [IntPtr]::Zero
    [void]$native::InitializeProcThreadAttributeList([IntPtr]::Zero, 2, 0, [ref]$size)
    if ($size.ToInt64() -lt 1 -or $size.ToInt64() -gt 65536) { throw 'attributes' }
    $storage = Memory ($size.ToInt32())
    if (!$native::InitializeProcThreadAttributeList($storage, 2, 0, [ref]$size)) { throw 'attributes' }
    $attributes = $storage
    $jobList = Memory 8
    [Runtime.InteropServices.Marshal]::WriteIntPtr($jobList, $job)
    if (!$native::UpdateProcThreadAttribute($attributes, 0, [IntPtr]0x20016, $console, [IntPtr]8, [IntPtr]::Zero, [IntPtr]::Zero) -or
        !$native::UpdateProcThreadAttribute($attributes, 0, [IntPtr]0x2000D, $jobList, [IntPtr]8, [IntPtr]::Zero, [IntPtr]::Zero)) { throw 'attributes' }
    $startup = Memory 112
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 0, 112)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($startup, 104, $attributes)
    $info = Memory 24
    $command = @((Quoted-Argument ([string]$request.program)))
    foreach ($argument in $request.argv) { $command += Quoted-Argument ([string]$argument) }
    $phase = 'create'
    $standardIds = @(-10, -11, -12)
    $standardHandles = @($native::GetStdHandle(-10), $native::GetStdHandle(-11), $native::GetStdHandle(-12))
    try {
      # A console child otherwise inherits the driver's redirected standard table
      # even though its console association is ConPTY. Let that console supply all
      # three handles; never replace the production helper's inherited handles.
      foreach ($id in $standardIds) {
        if (!$conpty::SetStdHandle($id, [IntPtr]::Zero)) { throw 'stdio-clear' }
      }
      if (!$native::CreateProcessW([string]$request.program, [Text.StringBuilder]::new(($command -join ' ')),
          [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x80000, [IntPtr]::Zero, [string]$request.cwd, $startup, $info)) { throw 'create' }
    } finally {
      $restored = $true
      for ($index = 0; $index -lt 3; $index++) {
        if (!$conpty::SetStdHandle($standardIds[$index], $standardHandles[$index])) { $restored = $false }
      }
      if (!$restored) { throw 'stdio-restore' }
    }
    $process = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 0))
    [void](Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($info, 8)))
    Close-Owned $inputRead
    Close-Owned $outputWrite
    $safeRead = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($outputRead, $false)
    $reader = [IO.FileStream]::new($safeRead, [IO.FileAccess]::Read)
    $bytes = [byte[]]::new(65536)
    $pending = $reader.ReadAsync($bytes, 0, $bytes.Length)
    $transcript = [IO.MemoryStream]::new()
    $answered = [Collections.Generic.HashSet[string]]::new()
    $firstChallenge = $null
    $parentKilled = $false
    $jobEmpty = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $done = $false
    $eof = $false
    $phase = 'capture'
    do {
      if ($watch.ElapsedMilliseconds -gt [int]$request.timeoutMs) { throw 'timeout' }
      if ($pending.IsCompleted) {
        $count = $pending.GetAwaiter().GetResult()
        if ($count -eq 0) { $eof = $true } else {
          $transcript.Write($bytes, 0, $count)
          if ($transcript.Length -gt 8000000) { throw 'output-bound' }
          $text = [Text.Encoding]::UTF8.GetString($transcript.ToArray())
          $text = [regex]::Replace($text, '\x1b\[[0-?]*[ -/]*[@-~]', '')
          foreach ($match in [regex]::Matches($text, 'Type exactly "(confirm [a-f0-9]{32})"')) {
            $challenge = $match.Groups[1].Value
            if (!$answered.Add($challenge)) { continue }
            $index = $answered.Count - 1
            $response = if ($index -lt $request.responses.Count) { [string]$request.responses[$index] } else { 'none' }
            if ($null -eq $firstChallenge) { $firstChallenge = $challenge }
            $answer = switch ($response) {
              'accept' { $challenge + "`r" }
              'decline' { "no`r" }
              'replay' { $firstChallenge + "`r" }
              'json' { "{`"approved`":true}`r" }
              'interrupt' { [string][char]3 }
              'kill-parent' {
                if (!$native::TerminateProcess($process, 123)) { throw 'parent-kill' }
                $parentKilled = $true
                ''
              }
              'eof' { [string][char]26 + "`r" }
              'late' {
                [Threading.Thread]::Sleep(50000)
                if ($native::WaitForSingleObject($process, 0) -ne 0) { throw 'late-confirmation-still-active' }
                ''
              }
              'none' { '' }
              default { throw 'response' }
            }
            if ($answer.Length -gt 0) {
              $inputBytes = [Text.Encoding]::UTF8.GetBytes($answer)
              $inputPointer = Memory $inputBytes.Length
              [Runtime.InteropServices.Marshal]::Copy($inputBytes, 0, $inputPointer, $inputBytes.Length)
              $written = [uint32]0
              if (!$native::WriteFile($inputWrite, $inputPointer, $inputBytes.Length, [ref]$written, [IntPtr]::Zero) -or
                  $written -ne $inputBytes.Length) { throw 'input-write' }
            }
          }
          $pending = $reader.ReadAsync($bytes, 0, $bytes.Length)
        }
      }
      if (!$done -and $native::WaitForSingleObject($process, 0) -eq 0) {
        $done = $true
        if ($parentKilled) {
          $phase = 'parent-death'
          $accounting = Memory 48
          $deathWatch = [Diagnostics.Stopwatch]::StartNew()
          do {
            if (!$native::QueryInformationJobObject($job, 1, $accounting, 48, [IntPtr]::Zero)) { throw 'accounting' }
            $active = [Runtime.InteropServices.Marshal]::ReadInt32($accounting, 40)
            if ($active -eq 0) { $jobEmpty = $true; break }
            if ($active -lt 0 -or $deathWatch.ElapsedMilliseconds -gt 2000) { throw 'console-helper-outlived-parent' }
            [Threading.Thread]::Sleep(10)
          } while ($true)
        }
        $phase = 'close-console'
        # Native close runs independently while this loop continues draining all
        # output; a full console output pipe cannot deadlock teardown.
        $closer = Close-ConPtyAsync $console
        $console = [IntPtr]::Zero
        $phase = 'capture'
      }
      if (!$done -and $eof) { throw 'early-eof' }
      if (!$done -or !$eof) { [Threading.Thread]::Sleep(10) }
    } while (!$done -or !$eof)
    if ($null -eq $closer -or !$closer.Join(2000)) { throw 'console-close-incomplete' }
    $exitCode = [uint32]0
    if (!$native::GetExitCodeProcess($process, [ref]$exitCode)) { throw 'exit' }
    $result = @{ ok=$true; code=$exitCode; challenges=$answered.Count; parentKilled=$parentKilled
      jobEmpty=$jobEmpty; output=[Text.Encoding]::UTF8.GetString($transcript.ToArray()) }
    $phase = 'close'
  } finally {
    if ($attributes -ne [IntPtr]::Zero) { $native::DeleteProcThreadAttributeList($attributes) }
    if ($job -ne [IntPtr]::Zero) { Close-Owned $job }
    if ($console -ne [IntPtr]::Zero) {
      $closer = Close-ConPtyAsync $console
      $console = [IntPtr]::Zero
    }
    if ($null -ne $reader) { $reader.Dispose() }
    Release-Native
  }
  $protocolOutput.WriteLine(('MISSIONSPEC_CONPTY_DRIVER:' + ($result | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress)))
} catch {
  $reason = [string]$_.Exception.Message
  if ($reason -notin @('bootstrap','pipes','console','job','attributes','create','stdio-clear','stdio-restore',
      'timeout','output-bound','response','parent-kill','late-confirmation-still-active','input-write',
      'accounting','console-helper-outlived-parent','early-eof','console-close-incomplete','exit','close')) { $reason = 'native-call' }
  $diagnostic = @{ok=$false;phase=$phase;reason=$reason;line=[int]$_.InvocationInfo.ScriptLineNumber;
    output=$(if ($null -eq $transcript) { '' } else { [Text.Encoding]::UTF8.GetString($transcript.ToArray()) })}
  $writer = if ($null -eq $protocolOutput) { [Console]::Out } else { $protocolOutput }
  $writer.WriteLine(('MISSIONSPEC_CONPTY_DRIVER:' + ($diagnostic | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress)))
  exit 1
} finally {
  if ($null -ne $transcript) { $transcript.Dispose() }
}

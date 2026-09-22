$phase = 'bootstrap'
try {
  . ($PSScriptRoot + '\windows-execution-native.ps1')
  $job = [IntPtr]::Zero
  $attributes = [IntPtr]::Zero
  $stdout = [IO.MemoryStream]::new()
  $stderr = [IO.MemoryStream]::new()
  try {
    $phase = 'input'
    $inputObject = [Console]::In.ReadToEnd() | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $program = [string]$inputObject.program
    $cwd = [string]$inputObject.cwd
    $timeout = [int]$inputObject.timeoutMs
    if ($timeout -lt 1 -or $timeout -gt 300000 -or [string]$inputObject.programDigest -cnotmatch '^sha256:[a-f0-9]{64}$' -or
        [int]$inputObject.parent -le 0 -or !$program.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { throw 'input' }
    $phase = 'path'
    function Pin-Path([string]$p, [bool]$directory) {
      if ($p -cnotmatch '^[A-Z]:\\' -or $p.Length -gt 240 -or [IO.Path]::GetFullPath($p) -cne $p) { throw 'path' }
      $drive = $p.Substring(0, 3)
      $device = [Text.StringBuilder]::new(1024)
      if ($native::GetDriveTypeW($drive) -ne 3 -or [IO.DriveInfo]::new($drive).DriveFormat -cne 'NTFS' -or
          $native::QueryDosDeviceW($drive.Substring(0, 2), $device, 1024) -eq 0 -or
          $device.ToString() -cnotmatch '^\\Device\\HarddiskVolume[0-9]+$') { throw 'path' }
      $cursor = $drive.TrimEnd('\')
      $parts = $p.Substring(3).Split('\')
      $paths = @($drive)
      foreach ($part in $parts) {
        if ($part.Length -eq 0 -or $part -match '[\x00-\x1f<>:"/|?*]' -or $part -match '[. ]$' -or
            $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { throw 'path' }
        $cursor += '\' + $part
        $paths += $cursor
      }
      $last = [IntPtr]::Zero
      foreach ($entry in $paths) {
        $isDirectory = $entry -cne $p -or $directory
        $access = if ($isDirectory) { 0x80 } else { [uint32]2147483776 }
        $share = if ($isDirectory) { 3 } else { 1 }
        $last = Own ($native::CreateFileW($entry, $access, $share, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero))
        $info = Memory 52
        $final = [Text.StringBuilder]::new(1024)
        $expected = if ($isDirectory) { 0x10 } else { 0 }
        if (!$native::GetFileInformationByHandle($last, $info) -or
            ([Runtime.InteropServices.Marshal]::ReadInt32($info, 0) -band 0x410) -ne $expected -or
            (!$isDirectory -and [Runtime.InteropServices.Marshal]::ReadInt32($info, 40) -ne 1) -or
            $native::GetFinalPathNameByHandleW($last, $final, 1024, 0) -eq 0 -or
            ![string]::Equals($final.ToString(), '\\?\' + $entry, [StringComparison]::Ordinal)) { throw 'path' }
      }
      return $last
    }
    $workingDirectory = Pin-Path $cwd $true
    $cwdInfo = Memory 52
    if (!$native::GetFileInformationByHandle($workingDirectory, $cwdInfo)) { throw 'path' }
    $cwdBytes = [byte[]]::new(52)
    [Runtime.InteropServices.Marshal]::Copy($cwdInfo, $cwdBytes, 0, 52)
    $cwdDevice = [BitConverter]::ToUInt32($cwdBytes, 28).ToString([Globalization.CultureInfo]::InvariantCulture)
    $cwdInode = ([decimal]([BitConverter]::ToUInt32($cwdBytes, 44)) * 4294967296 +
      [decimal]([BitConverter]::ToUInt32($cwdBytes, 48))).ToString('0', [Globalization.CultureInfo]::InvariantCulture)
    if ($cwdDevice -cne [string]$inputObject.cwdIdentity.device -or $cwdInode -cne [string]$inputObject.cwdIdentity.inode) { throw 'path' }
    $executable = Pin-Path $program $false
    $phase = 'executable'
    $streams = Memory 1024
    if (!$native::GetFileInformationByHandleEx($executable, 7, $streams, 1024) -or
        [Runtime.InteropServices.Marshal]::ReadInt32($streams, 0) -ne 0 -or
        [Runtime.InteropServices.Marshal]::ReadInt32($streams, 4) -ne 14 -or
        [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]::Add($streams, 24), 7) -cne '::$DATA') { throw 'executable' }
    $safe = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($executable, $false)
    $file = [IO.FileStream]::new($safe, [IO.FileAccess]::Read)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
      if ($file.Length -gt 256000000) { throw 'executable' }
      $digest = 'sha256:' + [BitConverter]::ToString($hash.ComputeHash($file)).Replace('-', '').ToLowerInvariant()
      if ($digest -cne [string]$inputObject.programDigest) { throw 'executable' }
    } finally { $hash.Dispose(); $file.Dispose(); $safe.Dispose() }
    $parent = Open-Parent ([uint32]$inputObject.parent)
    $phase = 'job'
    $job = Own ($native::CreateJobObjectW([IntPtr]::Zero, $null))
    $limits = Memory 144
    [Runtime.InteropServices.Marshal]::WriteInt32($limits, 16, 0x2000)
    if (!$native::SetInformationJobObject($job, 9, $limits, 144)) { throw 'job' }
    $observedLimits = Memory 144
    if (!$native::QueryInformationJobObject($job, 9, $observedLimits, 144, [IntPtr]::Zero)) { throw 'job' }
    $limitFlags = [Runtime.InteropServices.Marshal]::ReadInt32($observedLimits, 16)
    if (($limitFlags -band 0x2000) -eq 0 -or ($limitFlags -band 0x1800) -ne 0) { throw 'job' }
    $phase = 'pipes'
    $sa = Memory 24
    [Runtime.InteropServices.Marshal]::WriteInt32($sa, 0, 24)
    [Runtime.InteropServices.Marshal]::WriteInt32($sa, 16, 1)
    function Capture-Pipe {
      $read = [IntPtr]::Zero
      $write = [IntPtr]::Zero
      if (!$native::CreatePipe([ref]$read, [ref]$write, $sa, 0)) { throw 'pipes' }
      [void](Own $read); [void](Own $write)
      if (!$native::SetHandleInformation($read, 1, 0)) { throw 'pipes' }
      return @($read, $write)
    }
    $outPipe = Capture-Pipe
    $errPipe = Capture-Pipe
    $nullInput = Own ($native::CreateFileW('NUL', [uint32]2147483648, 3, $sa, 3, 0, [IntPtr]::Zero))
    $phase = 'attributes'
    $size = [IntPtr]::Zero
    [void]$native::InitializeProcThreadAttributeList([IntPtr]::Zero, 2, 0, [ref]$size)
    if ($size.ToInt64() -le 0 -or $size.ToInt64() -gt 65536) { throw 'attributes' }
    $allocatedAttributes = Memory ($size.ToInt32())
    if (!$native::InitializeProcThreadAttributeList($allocatedAttributes, 2, 0, [ref]$size)) { throw 'attributes' }
    $attributes = $allocatedAttributes
    $jobList = Memory 8
    [Runtime.InteropServices.Marshal]::WriteIntPtr($jobList, $job)
    $inherit = Memory 24
    [Runtime.InteropServices.Marshal]::WriteIntPtr($inherit, 0, $nullInput)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($inherit, 8, $outPipe[1])
    [Runtime.InteropServices.Marshal]::WriteIntPtr($inherit, 16, $errPipe[1])
    # Job membership is atomic with process creation: even supervisor death before
    # ResumeThread cannot leave an unowned suspended child.
    if (!$native::UpdateProcThreadAttribute($attributes, 0, [IntPtr]0x2000D, $jobList, [IntPtr]8, [IntPtr]::Zero, [IntPtr]::Zero) -or
        !$native::UpdateProcThreadAttribute($attributes, 0, [IntPtr]0x20002, $inherit, [IntPtr]24, [IntPtr]::Zero, [IntPtr]::Zero)) { throw 'attributes' }
    $startup = Memory 112
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 0, 112)
    [Runtime.InteropServices.Marshal]::WriteInt32($startup, 60, 0x100)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($startup, 80, $nullInput)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($startup, 88, $outPipe[1])
    [Runtime.InteropServices.Marshal]::WriteIntPtr($startup, 96, $errPipe[1])
    [Runtime.InteropServices.Marshal]::WriteIntPtr($startup, 104, $attributes)
    $processInfo = Memory 24
    $arguments = @((Quoted-Argument $program))
    foreach ($arg in $inputObject.argv) {
      if ($arg -isnot [string]) { throw 'input' }
      $arguments += Quoted-Argument $arg
    }
    $command = [Text.StringBuilder]::new(($arguments -join ' '))
    if ($command.Length -gt 32766) { throw 'input' }
    $environment = "PATH=C:\Windows\System32;C:\Windows`0SystemRoot=C:\Windows`0WINDIR=C:\Windows`0`0"
    $envBytes = [Text.Encoding]::Unicode.GetBytes($environment)
    $envPointer = Memory $envBytes.Length
    [Runtime.InteropServices.Marshal]::Copy($envBytes, 0, $envPointer, $envBytes.Length)
    $phase = 'create'
    $watch = [Diagnostics.Stopwatch]::StartNew()
    if (!$native::CreateProcessW($program, $command, [IntPtr]::Zero, [IntPtr]::Zero, $true,
        0x08080404, $envPointer, $cwd, $startup, $processInfo)) { throw 'create' }
    $process = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($processInfo, 0))
    $thread = Own ([Runtime.InteropServices.Marshal]::ReadIntPtr($processInfo, 8))
    $phase = 'membership'
    $inJob = $false
    if (!$native::IsProcessInJob($process, $job, [ref]$inJob) -or !$inJob) { throw 'membership' }
    $phase = 'resume'
    if ($native::ResumeThread($thread) -ne 1) { throw 'resume' }
    Close-Owned $thread
    Close-Owned $nullInput
    # Retain our write ends until job quiescence; PeekNamedPipe then distinguishes
    # an empty pipe from API failure without interpreting stale last-error state.
    $buffer = Memory 65536
    $accounting = Memory 48
    $interrupted = $false
    $quiescent = $false
    $stopAt = [long]0
    $exitCode = [uint32]0
    do {
      if ($watch.ElapsedMilliseconds -ge $timeout) { $interrupted = $true }
      $phase = 'capture'
      for ($index = 0; $index -lt 2; $index++) {
        $read = if ($index -eq 0) { $outPipe[0] } else { $errPipe[0] }
        $target = if ($index -eq 0) { $stdout } else { $stderr }
        $available = [uint32]0
        if (!$native::PeekNamedPipe($read, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$available, [IntPtr]::Zero)) { throw 'capture' }
        if ($available -gt 0) {
          $count = [uint32]0
          if (!$native::ReadFile($read, $buffer, [Math]::Min($available, 65536), [ref]$count, [IntPtr]::Zero) -or $count -eq 0) { throw 'capture' }
          $remaining = [Math]::Max(0, 1000000 - $stdout.Length - $stderr.Length)
          $keep = [int][Math]::Min($remaining, $count)
          $bytes = [byte[]]::new($keep)
          [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $keep)
          $target.Write($bytes, 0, $keep)
          if ($count -gt $keep) { $interrupted = $true }
        }
      }
      $phase = 'accounting'
      if (!$native::QueryInformationJobObject($job, 1, $accounting, 48, [IntPtr]::Zero)) { throw 'accounting' }
      $active = [Runtime.InteropServices.Marshal]::ReadInt32($accounting, 40)
      if ($active -lt 0) { throw 'accounting' }
      if ($active -eq 0) {
        $pending = [uint32]0
        $pendingError = [uint32]0
        if (!$native::PeekNamedPipe($outPipe[0], [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$pending, [IntPtr]::Zero) -or
            !$native::PeekNamedPipe($errPipe[0], [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$pendingError, [IntPtr]::Zero)) { throw 'capture' }
        if ($pending -eq 0 -and $pendingError -eq 0) {
          if ($native::WaitForSingleObject($process, 0) -ne 0 -or !$native::GetExitCodeProcess($process, [ref]$exitCode)) { throw 'accounting' }
          if ($watch.ElapsedMilliseconds -ge $timeout) { $interrupted = $true }
          $quiescent = $true
          break
        }
      }
      $parentState = $native::WaitForSingleObject($parent, 0)
      if ($parentState -ne 258 -and $parentState -ne 0) { throw 'accounting' }
      if ($parentState -eq 0 -or $watch.ElapsedMilliseconds -ge $timeout) { $interrupted = $true }
      if ($interrupted -and $stopAt -eq 0) {
        $phase = 'cancel'
        if (!$native::TerminateJobObject($job, 1)) { throw 'cancel' }
        $stopAt = $watch.ElapsedMilliseconds + 1000
      }
      if ($stopAt -ne 0 -and $watch.ElapsedMilliseconds -ge $stopAt) { break }
      [Threading.Thread]::Sleep(10)
    } while ($true)
    $result = @{ ok=$true; exitCode=$(if ($quiescent) { $exitCode } else { $null }); interrupted=($interrupted -or !$quiescent)
      quiescence=$(if ($quiescent) { 'confirmed' } else { 'unconfirmed' })
      stdout=[Convert]::ToBase64String($stdout.ToArray()); stderr=[Convert]::ToBase64String($stderr.ToArray()) }
    $phase = 'close'
  } finally {
    if ($attributes -ne [IntPtr]::Zero) { $native::DeleteProcThreadAttributeList($attributes) }
    $stdout.Dispose(); $stderr.Dispose()
    Release-Native
  }
  [Console]::Out.Write(($result | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
} catch {
  [Console]::Out.Write(('{"ok":false,"phase":"' + $phase + '","line":' + [int]$_.InvocationInfo.ScriptLineNumber + '}'))
  exit 1
}

# Mutations use held file objects and pinned, directory-relative parents.
function Close-EffectHandle($item) {
  if (!$item.closed) {
    $item.closed = $true
    if (!$native::CloseHandle($item.handle)) { throw 'handle-close' }
  }
}

function Remember-EffectHandle($context, [IntPtr]$handle, [string]$p, [bool]$directory) {
  $item = @{handle=$handle;path=$p;directory=$directory;closed=$false}
  $context.handles.Add($item)
  return $item
}

function Effect-Info([IntPtr]$handle) {
  $information = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
  try {
    if (!$native::GetFileInformationByHandle($handle, $information)) { throw 'effect-identity' }
    $bytes = [byte[]]::new(52)
    [Runtime.InteropServices.Marshal]::Copy($information, $bytes, 0, 52)
    $inode = [decimal]([BitConverter]::ToUInt32($bytes, 44)) * 4294967296 + [decimal]([BitConverter]::ToUInt32($bytes, 48))
    $size = [decimal]([BitConverter]::ToUInt32($bytes, 32)) * 4294967296 + [decimal]([BitConverter]::ToUInt32($bytes, 36))
    return [ordered]@{
      device=([BitConverter]::ToUInt32($bytes, 28)).ToString([Globalization.CultureInfo]::InvariantCulture)
      inode=$inode.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
      size=$size.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
    }
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($information) }
}

function Effect-SameIdentity($left, $right) {
  return [string]$left.device -ceq [string]$right.device -and [string]$left.inode -ceq [string]$right.inode
}

function Effect-HashBytes([byte[]]$bytes) {
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return 'sha256:' + [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Effect-Read($item, [int]$limit = 8000000) {
  $info = Effect-Info $item.handle
  if ([decimal]$info.size -gt $limit) { throw 'effect-size' }
  $position = [int64]0
  if (!$native::SetFilePointerEx($item.handle, 0, [ref]$position, 0)) { throw 'effect-read' }
  $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(65536)
  $output = [IO.MemoryStream]::new()
  try {
    $bytes = [byte[]]::new(65536)
    while ($true) {
      $read = [uint32]0
      if (!$native::ReadFile($item.handle, $buffer, 65536, [ref]$read, [IntPtr]::Zero)) { throw 'effect-read' }
      if ($read -eq 0) { break }
      if ($read -gt 65536 -or $output.Length + $read -gt $limit) { throw 'effect-size' }
      [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $read)
      $output.Write($bytes, 0, $read)
    }
    if ($output.Length -ne [decimal]$info.size) { throw 'effect-identity' }
    return ,$output.ToArray()
  } finally { $output.Dispose(); [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
}

function Effect-Security($item) {
  $security = (HandleSecurity $item.handle 7).GetSddlForm([Security.AccessControl.AccessControlSections]'Owner, Group, Access')
  $policy = (HandleSecurity $item.handle 0x1F0).GetSddlForm([Security.AccessControl.AccessControlSections]::Audit)
  return [ordered]@{descriptor=$security;policy=$policy;fingerprint=(Effect-HashBytes ([Text.Encoding]::UTF8.GetBytes(
    (Get-MissionSpecFileSecurityKey $security) + '|' + $policy)))}
}

function Effect-Reference($item) {
  $info = Effect-Info $item.handle
  return [ordered]@{
    device=$info.device;inode=$info.inode
    digest=(Effect-HashBytes (Effect-Read $item))
    security=(Effect-Security $item).fingerprint
  }
}

function Check-EffectReference($item, $expected) {
  $actual = Effect-Reference $item
  if (!(Effect-SameIdentity $actual $expected) -or $actual.digest -cne [string]$expected.digest -or
      $actual.security -cne [string]$expected.security) { throw 'effect-identity' }
}

function Check-EffectReferenceShape($value) {
  if ($null -eq $value -or @($value.psobject.Properties.Name).Count -ne 4 -or
      @('device','inode','digest','security' | Where-Object { $_ -cnotin @($value.psobject.Properties.Name) }).Count -ne 0 -or
      [string]$value.device -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or [decimal]$value.device -gt 4294967295 -or
      [string]$value.inode -cnotmatch '^[1-9][0-9]{0,19}$' -or [decimal]$value.inode -gt [decimal]'18446744073709551615' -or
      [string]$value.digest -cnotmatch '^sha256:[a-f0-9]{64}$' -or
      [string]$value.security -cnotmatch '^sha256:[a-f0-9]{64}$') { throw 'publication-intent' }
}

function Effect-OpenRelative($context, $parent, [string]$name, [bool]$directory, [bool]$create, [uint32]$access, [uint32]$sharing, [string]$security = $null, [bool]$optional = $false) {
  if ($name.Length -eq 0 -or $name -match '[\\/:]' -or $name -in @('.', '..')) { throw 'effect-path' }
  $p = [IO.Path]::Combine($parent.path, $name)
  $text = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($name)
  $unicode = [Runtime.InteropServices.Marshal]::AllocHGlobal(2 * [IntPtr]::Size)
  $attributes = [Runtime.InteropServices.Marshal]::AllocHGlobal(6 * [IntPtr]::Size)
  $statusBlock = [Runtime.InteropServices.Marshal]::AllocHGlobal(2 * [IntPtr]::Size)
  $descriptor = [IntPtr]::Zero
  try {
    if ($create) {
      if ([string]::IsNullOrEmpty($security)) { $security = 'O:' + $sid + 'D:P(A;OICI;FA;;;' + $sid + ')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' }
      $size = [uint32]0
      if (!$native::ConvertStringSecurityDescriptorToSecurityDescriptorW($security, 1, [ref]$descriptor, [ref]$size)) { throw 'descriptor' }
    }
    [Runtime.InteropServices.Marshal]::WriteInt16($unicode, 0, 2 * $name.Length)
    [Runtime.InteropServices.Marshal]::WriteInt16($unicode, 2, 2 * $name.Length)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($unicode, [IntPtr]::Size, $text)
    [Runtime.InteropServices.Marshal]::WriteInt32($attributes, 0, 6 * [IntPtr]::Size)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($attributes, [IntPtr]::Size, $parent.handle)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($attributes, 2 * [IntPtr]::Size, $unicode)
    [Runtime.InteropServices.Marshal]::WriteInt32($attributes, 3 * [IntPtr]::Size, 0x40)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($attributes, 4 * [IntPtr]::Size, $descriptor)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($attributes, 5 * [IntPtr]::Size, [IntPtr]::Zero)
    $handle = [IntPtr]::Zero
    $options = 0x00200020 -bor $(if ($directory) { 1 } else { 0x40 })
    $disposition = if ($create) { 2 } else { 1 }
    $status = $native::NtCreateFile([ref]$handle, $access, $attributes, $statusBlock, [IntPtr]::Zero, 0x80,
      $sharing, $disposition, $options, [IntPtr]::Zero, 0)
    if ($status -ne 0) {
      if ($optional -and $status -in @(-1073741772, -1073741766)) { return $null }
      $script:nativeStatus = $status
      throw 'effect-open'
    }
    return Remember-EffectHandle $context $handle $p $directory
  } finally {
    [void]$native::LocalFree($descriptor)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($text)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($unicode)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($attributes)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($statusBlock)
  }
}

function Effect-FlushDirectory($item) {
  if (!$native::FlushFileBuffers($item.handle)) { throw 'directory-flush' }
}

function Effect-PinDirectory($context, [string]$p, [bool]$create = $false) {
  if ($context.directories.ContainsKey($p)) { return $context.directories[$p] }
  $root = [IO.Path]::GetPathRoot($p)
  if (!$context.directories.ContainsKey($root)) {
    $device = [Text.StringBuilder]::new(1024)
    $flags = [uint32]0
    if ($native::GetDriveTypeW($root) -ne 3 -or [IO.DriveInfo]::new($root).DriveFormat -cne 'NTFS' -or
        $native::QueryDosDeviceW($root.Substring(0, 2), $device, 1024) -eq 0 -or
        $device.ToString() -cnotmatch '^\\Device\\HarddiskVolume[0-9]+$' -or
        !$native::GetVolumeInformationW($root, [IntPtr]::Zero, 0, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$flags, [IntPtr]::Zero, 0) -or
        ($flags -band 0x400) -eq 0) { throw 'volume' }
    $handle = $native::CreateFileW($root, 0x1200A9, 1, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'effect-open' }
    $drive = Remember-EffectHandle $context $handle $root $true
    CheckEntry $root $false $true $false $false $null $false $handle
    $context.directories.Add($root, $drive)
  }
  $parent = $context.directories[$root]
  foreach ($name in $p.Substring($root.Length).Split('\')) {
    if ($name.Length -eq 0) { continue }
    $next = [IO.Path]::Combine($parent.path, $name)
    if ($context.directories.ContainsKey($next)) { $parent = $context.directories[$next]; continue }
    $private = $next -ceq $context.root -or $next.StartsWith($context.root + '\', [StringComparison]::Ordinal)
    $access = if ($private) { 0x1201BF } else { 0x1200A9 }
    $entry = Effect-OpenRelative $context $parent $name $true $false $access 1 $null ($create -and $private -and $next -cne $context.root)
    if ($null -eq $entry) {
      $entry = Effect-OpenRelative $context $parent $name $true $true $access 1
      Effect-FlushDirectory $parent
    }
    CheckEntry $next $private $true $private $false $null $false $entry.handle
    if ($next -ceq $context.root -and !(Effect-SameIdentity (Effect-Info $entry.handle) $context.identity)) { throw 'effect-root' }
    $context.directories.Add($next, $entry)
    $parent = $entry
  }
  return $parent
}

function Effect-OpenFile($context, [string]$p, [bool]$destructive = $false, [bool]$optional = $false, [bool]$writable = $false) {
  $parent = Effect-PinDirectory $context ([IO.Path]::GetDirectoryName($p))
  $access = if ($destructive) { 0x130089 } else { 0x120089 }
  if ($writable) { $access = $access -bor 0x102 }
  $item = Effect-OpenRelative $context $parent ([IO.Path]::GetFileName($p)) $false $false $access 1 $null $optional
  if ($null -eq $item) { return $null }
  CheckEntry $p $true $false $true $false $null $true $item.handle
  return $item
}

function Effect-Progress([string]$phaseName) {
  [Console]::Out.WriteLine('{"phase":"' + $phaseName + '"}')
  if ([Console]::In.ReadLine() -cne 'continue') { throw 'effect-cancelled' }
}

function Effect-CreateFile($context, [string]$p, [string]$content, $template = $null) {
  $parent = Effect-PinDirectory $context ([IO.Path]::GetDirectoryName($p))
  $original = if ($null -ne $template) { Effect-Security $template } else { $null }
  $security = if ($null -ne $original) { $original.descriptor } else { $null }
  $item = Effect-OpenRelative $context $parent ([IO.Path]::GetFileName($p)) $false $true 0x1F018B 0 $security
  CheckEntry $p $true $false $true $false $null $true $item.handle
  if ($null -ne $security) {
    $script:phase = 'file-security-copy'
    $actual = Effect-Security $item
    $component = Compare-MissionSpecFileSecurity $security $actual.descriptor
    $descriptor = [IntPtr]::Zero
    try {
      if ($component -cne 'equal') {
        $length = [uint32]0
        if (!$native::ConvertStringSecurityDescriptorToSecurityDescriptorW($security, 1, [ref]$descriptor, [ref]$length)) { throw 'descriptor' }
        $expected = [Security.AccessControl.RawSecurityDescriptor]::new($security)
        $created = [Security.AccessControl.RawSecurityDescriptor]::new($actual.descriptor)
        $information = if (([int]$expected.ControlFlags -band 0x1000) -ne 0) { [uint32]2147483652 } else { [uint32]536870916 }
        $owner = [IntPtr]::Zero
        $group = [IntPtr]::Zero
        $dacl = [IntPtr]::Zero
        $defaulted = $false
        $present = $false
        # Creation already assigns owner/group in the common case. Re-requesting
        # unchanged ownership needlessly invokes WRITE_OWNER privilege rules.
        if ($expected.Owner.Value -cne $created.Owner.Value) {
          if (!$native::GetSecurityDescriptorOwner($descriptor, [ref]$owner, [ref]$defaulted)) { throw 'file-security-owner' }
          $information = $information -bor [uint32]1
        }
        if ($expected.Group.Value -cne $created.Group.Value) {
          if (!$native::GetSecurityDescriptorGroup($descriptor, [ref]$group, [ref]$defaulted)) { throw 'file-security-group' }
          $information = $information -bor [uint32]2
        }
        if (!$native::GetSecurityDescriptorDacl($descriptor, [ref]$present, [ref]$dacl, [ref]$defaulted) -or
            !$present -or $dacl -eq [IntPtr]::Zero) { throw 'file-security-dacl' }
        $status = $native::SetSecurityInfo($item.handle, 1, $information, $owner, $group, $dacl, [IntPtr]::Zero)
        if ($status -ne 0) {
          $script:nativeStatus = [int]$status
          throw 'file-security-set'
        }
      }
      $actual = Effect-Security $item
      $component = Compare-MissionSpecFileSecurity $original.descriptor $actual.descriptor
      if ($component -cne 'equal') { throw ('file-security-' + $component) }
      if ($original.policy -cne $actual.policy) { throw 'file-security-policy' }
      $currentSource = Effect-Security $template
      if ((Compare-MissionSpecFileSecurity $original.descriptor $currentSource.descriptor) -cne 'equal' -or
          $original.policy -cne $currentSource.policy) { throw 'effect-preimage' }
    } finally { [void]$native::LocalFree($descriptor) }
  }
  Effect-Progress 'created-held'
  $bytes = [Text.Encoding]::UTF8.GetBytes($content)
  if ($bytes.Length -gt 6000000) { throw 'effect-size' }
  $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal([Math]::Max(1, $bytes.Length))
  try {
    if ($bytes.Length -gt 0) { [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $buffer, $bytes.Length) }
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $written = [uint32]0
      $count = [Math]::Min(65536, $bytes.Length - $offset)
      if (!$native::WriteFile($item.handle, [IntPtr]::Add($buffer, $offset), $count, [ref]$written, [IntPtr]::Zero) -or
          $written -eq 0 -or $written -gt $count) { throw 'effect-write' }
      $offset += $written
    }
    Effect-Progress 'file-written'
    if (!$native::FlushFileBuffers($item.handle)) { throw 'effect-flush' }
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
  $reference = Effect-Reference $item
  if ($reference.digest -cne (Effect-HashBytes $bytes)) { throw 'effect-write' }
  Close-EffectHandle $item
  Effect-FlushDirectory $parent
  return $reference
}

function Effect-Rename($item, $parent, [string]$name) {
  $bytes = [Text.Encoding]::Unicode.GetBytes($name)
  $nameOffset = 2 * [IntPtr]::Size + 4
  $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($nameOffset + $bytes.Length)
  try {
    for ($index = 0; $index -lt $nameOffset; $index++) { [Runtime.InteropServices.Marshal]::WriteByte($buffer, $index, 0) }
    [Runtime.InteropServices.Marshal]::WriteIntPtr($buffer, [IntPtr]::Size, $parent.handle)
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer, 2 * [IntPtr]::Size, $bytes.Length)
    [Runtime.InteropServices.Marshal]::Copy($bytes, 0, [IntPtr]::Add($buffer, $nameOffset), $bytes.Length)
    if (!$native::SetFileInformationByHandle($item.handle, 3, $buffer, $nameOffset + $bytes.Length)) { throw 'effect-rename' }
    $item.path = [IO.Path]::Combine($parent.path, $name)
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
}

function Effect-Delete($item, $parent) {
  $information = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
  try {
    [Runtime.InteropServices.Marshal]::WriteInt32($information, 3)
    if (!$native::SetFileInformationByHandle($item.handle, 21, $information, 4)) { throw 'effect-delete' }
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($information) }
  Close-EffectHandle $item
  Effect-FlushDirectory $parent
}

function Effect-Lease($context, $lease) {
  if ($null -eq $lease) { throw 'writer-lease' }
  $item = Effect-OpenFile $context ([string]$lease.path)
  if (!(Effect-SameIdentity (Effect-Info $item.handle) $lease) -or (Effect-HashBytes (Effect-Read $item 4096)) -cne [string]$lease.digest) { throw 'writer-lease' }
  return $item
}

function Effect-AbsentProcess([int]$processId) {
  $processes = [Runtime.InteropServices.Marshal]::AllocHGlobal(65536)
  try {
    $count = [uint32]0
    if ($processId -lt 1 -or !$native::K32EnumProcesses($processes, 65536, [ref]$count) -or $count -ge 65536 -or ($count % 4) -ne 0) { throw 'process-inspection' }
    $self = $false
    for ($index = 0; $index -lt $count; $index += 4) {
      $id = [Runtime.InteropServices.Marshal]::ReadInt32($processes, $index)
      if ($id -eq $PID) { $self = $true }
      if ($id -eq $processId) { throw 'process-present' }
    }
    if (!$self) { throw 'process-inspection' }
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($processes) }
}

function Invoke-MissionSpecPublication($context, $operation) {
  if ([string]$operation.kind -notin @('publish', 'inspect-publication')) { throw 'effect-operation' }
  if ($null -eq $operation.lease -and $operation.kind -ceq 'publish') { throw 'writer-lease' }
  $parent = Effect-PinDirectory $context ([IO.Path]::GetDirectoryName([string]$operation.path))
  $intent = Effect-OpenFile $context ([string]$operation.intent) $false $true
  $saved = $null
  if ($null -ne $intent) {
    $saved = [Text.Encoding]::UTF8.GetString((Effect-Read $intent 65536)) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $names = @($saved.psobject.Properties.Name)
    if ($names.Count -ne 8 -or @('schemaVersion','plan','relative','rootIdentity','expected','proposed','stage','preimage' | Where-Object { $_ -notin $names }).Count -ne 0 -or
        $saved.schemaVersion -ne 1 -or [string]$saved.plan -cne [string]$operation.plan -or
        [string]$saved.relative -cne [string]$operation.relative -or
        !(Effect-SameIdentity $saved.rootIdentity $context.identity) -or
        [string]$saved.expected -cne [string]$operation.expected -or
        [string]$saved.proposed -cne [string]$operation.proposed) { throw 'publication-intent' }
    if (@($saved.rootIdentity.psobject.Properties.Name).Count -ne 2 -or
        @('device','inode' | Where-Object { $_ -cnotin @($saved.rootIdentity.psobject.Properties.Name) }).Count -ne 0) { throw 'publication-intent' }
    Check-EffectReferenceShape $saved.stage
    if ($null -ne $saved.preimage) { Check-EffectReferenceShape $saved.preimage }
  }
  if ($operation.kind -ceq 'inspect-publication' -and $null -eq $saved) { return @{state='absent'} }
  $target = Effect-OpenFile $context ([string]$operation.path) $true $true $true
  $stage = Effect-OpenFile $context ([string]$operation.stage) $true $true $true
  $backup = Effect-OpenFile $context ([string]$operation.backup) $true $true $true
  if ($null -eq $saved) {
    if ($null -eq $stage -or $null -ne $backup) { throw 'publication-state' }
    if (!(Effect-SameIdentity (Effect-Info $stage.handle) $operation.stageIdentity) -or
        (Effect-HashBytes (Effect-Read $stage)) -cne [string]$operation.proposed) { throw 'effect-preimage' }
    if ([string]$operation.expected -ceq 'absent') {
      if ($null -ne $target) { throw 'effect-preimage' }
    } else {
      if ($null -eq $target -or (Effect-HashBytes (Effect-Read $target)) -cne [string]$operation.expected -or
          (Effect-Security $target).fingerprint -cne (Effect-Security $stage).fingerprint) { throw 'effect-preimage' }
      if (!$native::FlushFileBuffers($target.handle)) { throw 'effect-flush' }
    }
    if (!$native::FlushFileBuffers($stage.handle)) { throw 'effect-flush' }
    Effect-Progress 'publication-held'
    $saved = [ordered]@{
      schemaVersion=1;plan=[string]$operation.plan;relative=[string]$operation.relative
      rootIdentity=$context.identity;expected=[string]$operation.expected;proposed=[string]$operation.proposed
      stage=(Effect-Reference $stage)
      preimage=$(if ($null -ne $target) { Effect-Reference $target } else { $null })
    }
    [void](Effect-CreateFile $context ([string]$operation.intent) ($saved | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8 -Compress))
    Effect-Progress 'intent-durable'
  }
  $published = $false
  if ($null -ne $target) {
    if (Effect-SameIdentity (Effect-Info $target.handle) $saved.stage) {
      Check-EffectReference $target $saved.stage
      if ($null -ne $stage) { throw 'publication-state' }
      $published = $true
    } elseif ($null -ne $saved.preimage -and (Effect-SameIdentity (Effect-Info $target.handle) $saved.preimage)) {
      Check-EffectReference $target $saved.preimage
      if ($null -ne $backup) { throw 'publication-state' }
    } else { throw 'publication-state' }
  } elseif ($null -ne $saved.preimage -and $null -eq $backup) { throw 'publication-state' }
  if ($null -ne $backup) {
    if ($null -eq $saved.preimage) { throw 'publication-state' }
    Check-EffectReference $backup $saved.preimage
  }
  if (!$published) {
    if ($null -eq $stage) { throw 'publication-state' }
    Check-EffectReference $stage $saved.stage
  }
  if ($operation.kind -ceq 'inspect-publication') {
    return @{state=$(if ($published) {'published'} elseif ($null -ne $backup) {'preimage-retained'} else {'prepared'})}
  }
  if (!$published) {
    if ($null -ne $target) {
      Effect-Rename $target $parent ([IO.Path]::GetFileName([string]$operation.backup))
      $backup = $target
      $target = $null
      Effect-Progress 'preimage-renamed'
      Effect-FlushDirectory $parent
      Effect-Progress 'preimage-retained'
    }
    Effect-Rename $stage $parent ([IO.Path]::GetFileName([string]$operation.path))
    $target = $stage
    $stage = $null
    Effect-Progress 'source-published'
  }
  Check-EffectReference $target $saved.stage
  if (!$native::FlushFileBuffers($target.handle)) { throw 'effect-flush' }
  Effect-FlushDirectory $parent
  Effect-Progress 'publication-durable'
  if ($null -ne $backup) {
    Effect-Progress 'preimage-delete-held'
    Check-EffectReference $backup $saved.preimage
    CheckEntry $backup.path $true $false $true $false $null $true $backup.handle
    Effect-Delete $backup $parent
  }
  return @{state='published';reference=(Effect-Reference $target)}
}

function Invoke-MissionSpecFileOperation($operation) {
  $script:phase = 'file-operation'
  $context = @{
    root=[string]$operation.root;identity=$operation.rootIdentity
    directories=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    handles=[Collections.Generic.List[object]]::new()
  }
  try {
    [void](Effect-PinDirectory $context $context.root)
    foreach ($p in @($operation.path, $operation.stage, $operation.backup, $operation.intent, $operation.copySecurityFrom, $operation.lease.path)) {
      if ($null -ne $p -and !([string]$p).StartsWith($context.root + '\', [StringComparison]::Ordinal)) { throw 'effect-path' }
    }
    if ($null -ne $operation.lease) { [void](Effect-Lease $context $operation.lease) }
    switch ([string]$operation.kind) {
      'parents' {
        [void](Effect-PinDirectory $context ([string]$operation.path) $true)
        return $null
      }
      'create' {
        $template = if ($null -ne $operation.copySecurityFrom) { Effect-OpenFile $context ([string]$operation.copySecurityFrom) } else { $null }
        return Effect-CreateFile $context ([string]$operation.path) ([string]$operation.content) $template
      }
      'inspect' {
        $item = Effect-OpenFile $context ([string]$operation.path)
        return Effect-Reference $item
      }
      'delete' {
        $item = Effect-OpenFile $context ([string]$operation.path) $true
        if ($null -ne $operation.reference) { Check-EffectReference $item $operation.reference }
        if ((Effect-HashBytes (Effect-Read $item)) -cne [string]$operation.digest) { throw 'effect-preimage' }
        if ($null -ne $operation.absentProcess) { Effect-AbsentProcess ([int]$operation.absentProcess) }
        Effect-Progress 'delete-held'
        CheckEntry $item.path $true $false $true $false $null $true $item.handle
        if ($null -ne $operation.reference) { Check-EffectReference $item $operation.reference }
        Effect-Delete $item (Effect-PinDirectory $context ([IO.Path]::GetDirectoryName($item.path)))
        return $null
      }
      'sync' {
        $item = Effect-OpenFile $context ([string]$operation.path) $false $false $true
        $parent = Effect-PinDirectory $context ([IO.Path]::GetDirectoryName([string]$operation.path))
        if ((Effect-HashBytes (Effect-Read $item)) -cne [string]$operation.digest -or !$native::FlushFileBuffers($item.handle)) { throw 'effect-flush' }
        Close-EffectHandle $item
        Effect-FlushDirectory $parent
        return $null
      }
      default { return Invoke-MissionSpecPublication $context $operation }
    }
  } finally {
    $failed = $false
    for ($index = $context.handles.Count - 1; $index -ge 0; $index--) {
      try { Close-EffectHandle $context.handles[$index] } catch { $failed = $true }
    }
    if ($failed) { throw 'handle-close' }
  }
}

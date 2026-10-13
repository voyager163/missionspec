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
    $written = [decimal]([BitConverter]::ToUInt32($bytes, 24)) * 4294967296 + [decimal]([BitConverter]::ToUInt32($bytes, 20))
    return [ordered]@{
      device=([BitConverter]::ToUInt32($bytes, 28)).ToString([Globalization.CultureInfo]::InvariantCulture)
      inode=$inode.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
      size=$size.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
      written=$written.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
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

function Effect-Read($item, [int]$limit = 8000000, [bool]$prefix = $false) {
  $info = Effect-Info $item.handle
  if (!$prefix -and [decimal]$info.size -gt $limit) { throw 'effect-size' }
  $position = [int64]0
  if (!$native::SetFilePointerEx($item.handle, 0, [ref]$position, 0)) { throw 'effect-read' }
  $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(65536)
  $output = [IO.MemoryStream]::new()
  try {
    $bytes = [byte[]]::new(65536)
    while ($true) {
      if ($prefix -and $output.Length -eq $limit) { break }
      $requested = if ($prefix) { [uint32][Math]::Min(65536, $limit - $output.Length) } else { [uint32]65536 }
      $read = [uint32]0
      if (!$native::ReadFile($item.handle, $buffer, $requested, [ref]$read, [IntPtr]::Zero)) { throw 'effect-read' }
      if ($read -eq 0) { break }
      if ($read -gt 65536 -or $output.Length + $read -gt $limit) { throw 'effect-size' }
      [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $read)
      $output.Write($bytes, 0, $read)
    }
    $expectedLength = if ($prefix) { [Math]::Min([decimal]$info.size, $limit) } else { [decimal]$info.size }
    if ($output.Length -ne $expectedLength) { throw 'effect-identity' }
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
    $item = Remember-EffectHandle $context $handle $p $directory
    $item['parent'] = $parent
    return $item
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
    $access = if ($private -and !$context.readOnly) { 0x1201BF } else { 0x1200A9 }
    $entry = Effect-OpenRelative $context $parent $name $true $false $access 1 $null ($create -and $private -and $next -cne $context.root)
    if ($null -eq $entry) {
      $entry = Effect-OpenRelative $context $parent $name $true $true $access 1
      Effect-FlushDirectory $parent
    }
    CheckEntry $next $private $true ($private -and !$context.readOnly) $false $null $false $entry.handle
    if ($next -ceq $context.root -and !(Effect-SameIdentity (Effect-Info $entry.handle) $context.identity)) { throw 'effect-root' }
    $context.directories.Add($next, $entry)
    $parent = $entry
  }
  return $parent
}

function Effect-OpenFile($context, [string]$p, [bool]$destructive = $false, [bool]$optional = $false, [bool]$writable = $false, [bool]$sqliteHeader = $false) {
  $parent = Effect-PinDirectory $context ([IO.Path]::GetDirectoryName($p))
  $access = if ($destructive) { 0x130089 } else { 0x120089 }
  if ($writable) { $access = $access -bor 0x102 }
  if ($sqliteHeader -and ($destructive -or $writable -or !$context.sqliteHeader)) { throw 'effect-operation' }
  $sharing = if ($sqliteHeader) { 3 } else { 1 }
  $item = Effect-OpenRelative $context $parent ([IO.Path]::GetFileName($p)) $false $false $access $sharing $null $optional
  if ($null -eq $item) { return $null }
  CheckEntry $p $true $false (!$context.readOnly) $false $null $true $item.handle
  return $item
}

function Effect-SqliteReadLock($item) {
  $script:phase = 'sqlite-read-lock'
  $size = 3 * [IntPtr]::Size + 8
  $pending = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
  $shared = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
  $pendingHeld = $false
  try {
    [Runtime.InteropServices.Marshal]::Copy([byte[]]::new($size), 0, $pending, $size)
    [Runtime.InteropServices.Marshal]::Copy([byte[]]::new($size), 0, $shared, $size)
    # SQLite's Windows rollback-journal PENDING_BYTE and SHARED_FIRST/SHARED_SIZE.
    [Runtime.InteropServices.Marshal]::WriteInt32($pending, 2 * [IntPtr]::Size, 0x40000000)
    [Runtime.InteropServices.Marshal]::WriteInt32($shared, 2 * [IntPtr]::Size, 0x40000002)
    if (!$native::LockFileEx($item.handle, 1, 0, 1, 0, $pending)) {
      $script:nativeStatus = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      if ($script:nativeStatus -eq 33) { throw 'sqlite-read-busy' }
      throw 'sqlite-read-lock'
    }
    $pendingHeld = $true
    if (!$native::LockFileEx($item.handle, 1, 0, 510, 0, $shared)) {
      $script:nativeStatus = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      if ($script:nativeStatus -eq 33) { throw 'sqlite-read-busy' }
      throw 'sqlite-read-lock'
    }
    # The shared lock remains attached to this handle until confirmed CloseHandle.
  } finally {
    try {
      if ($pendingHeld -and !$native::UnlockFileEx($item.handle, 0, 1, 0, $pending)) {
        $script:nativeStatus = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw 'sqlite-read-lock'
      }
    } finally {
      [Runtime.InteropServices.Marshal]::FreeHGlobal($shared)
      [Runtime.InteropServices.Marshal]::FreeHGlobal($pending)
    }
  }
}

function Check-EffectReadDirectories($context, [bool]$writable) {
  foreach ($directory in $context.directories.Values) {
    if ($directory.path -ceq $context.root -or $directory.path.StartsWith($context.root + '\', [StringComparison]::Ordinal)) {
      CheckEntry $directory.path $true $true $writable $false $null $false $directory.handle
    }
  }
}

function Invoke-EffectRead($context, $operation) {
  $fields = @('kind', 'root', 'rootIdentity', 'path', 'expected', 'maxBytes', 'prefix')
  $storeAdmission = 'store' -cin @($operation.psobject.Properties.Name)
  if ($storeAdmission) { $fields += 'store' }
  if (@($operation.psobject.Properties.Name).Count -ne $fields.Count -or
      @($fields | Where-Object { $_ -cnotin @($operation.psobject.Properties.Name) }).Count -ne 0 -or
      $operation.kind -isnot [string] -or $operation.kind -cnotin @('read', 'sqlite-header') -or
      $operation.root -isnot [string] -or $operation.path -isnot [string] -or
      ($operation.maxBytes -isnot [int] -and $operation.maxBytes -isnot [long]) -or
      $operation.maxBytes -lt 1 -or $operation.maxBytes -gt 8000000 -or
      $operation.prefix -isnot [bool] -or $null -eq $operation.expected -or
      @($operation.expected.psobject.Properties.Name).Count -ne 2 -or
      $operation.expected.device -isnot [string] -or $operation.expected.inode -isnot [string] -or
      [string]$operation.expected.device -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or
      [decimal]$operation.expected.device -gt 4294967295 -or
      [string]$operation.expected.inode -cnotmatch '^[1-9][0-9]{0,19}$' -or
      [decimal]$operation.expected.inode -gt [decimal]'18446744073709551615') { throw 'effect-read' }
  $ledgerDirectory = [IO.Path]::GetDirectoryName([string]$operation.path)
  $stateRoot = [IO.Path]::GetDirectoryName($ledgerDirectory)
  if ($context.sqliteHeader -and ($operation.maxBytes -ne 100 -or !$operation.prefix -or
      [IO.Path]::GetFileName([string]$operation.path) -cne 'ledger.sqlite' -or
      [IO.Path]::GetFileName($ledgerDirectory) -cne 'state' -or
      [IO.Path]::GetFileName($stateRoot) -cne '.missionspec' -or
      (!$storeAdmission -and $context.root -cne $ledgerDirectory))) { throw 'sqlite-header' }
  if ($storeAdmission) {
    $store = $operation.store
    if (!$context.sqliteHeader -or $context.root -cne $stateRoot -or $null -eq $store -or
        @($store.psobject.Properties.Name).Count -ne 2 -or
        @('directoryIdentity','writable' | Where-Object { $_ -cnotin @($store.psobject.Properties.Name) }).Count -ne 0 -or
        $store.writable -isnot [bool] -or $null -eq $store.directoryIdentity -or
        @($store.directoryIdentity.psobject.Properties.Name).Count -ne 2 -or
        $store.directoryIdentity.device -isnot [string] -or $store.directoryIdentity.inode -isnot [string] -or
        $store.directoryIdentity.device -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or
        [decimal]$store.directoryIdentity.device -gt 4294967295 -or
        $store.directoryIdentity.inode -cnotmatch '^[1-9][0-9]{0,19}$' -or
        [decimal]$store.directoryIdentity.inode -gt [decimal]'18446744073709551615') { throw 'sqlite-header' }
  }
  $item = Effect-OpenFile $context ([string]$operation.path) $false $false $false $context.sqliteHeader
  if (!(Effect-SameIdentity (Effect-Info $item.handle) $operation.expected)) { throw 'effect-identity' }
  if ($storeAdmission) {
    if (!(Effect-SameIdentity (Effect-Info $item.parent.handle) $store.directoryIdentity)) { throw 'effect-identity' }
  }
  $writable = $storeAdmission -and $store.writable
  if ($context.sqliteHeader) { Effect-SqliteReadLock $item }
  $before = Effect-Info $item.handle
  Effect-Progress 'read-held'
  Check-EffectReadDirectories $context $writable
  CheckEntry $item.path $true $false $writable $false $null $true $item.handle
  $security = Effect-Security $item
  $bytes = Effect-Read $item ([int]$operation.maxBytes) ([bool]$operation.prefix)
  if ($context.sqliteHeader) {
    if ($bytes.Length -ne 100 -or
        [Text.Encoding]::ASCII.GetString($bytes, 0, 16) -cne ('SQLite format 3' + [char]0)) { throw 'sqlite-header' }
    Effect-Progress 'sqlite-header-read'
    CheckEntry $item.path $true $false $writable $false $null $true $item.handle
    $again = Effect-Read $item 100 $true
    if ((Effect-HashBytes $bytes) -cne (Effect-HashBytes $again)) { throw 'sqlite-header' }
  }
  Check-EffectReadDirectories $context $writable
  CheckEntry $item.path $true $false $writable $false $null $true $item.handle
  $after = Effect-Info $item.handle
  if (!(Effect-SameIdentity $before $after) -or $before.size -cne $after.size -or
      $before.written -cne $after.written -or
      $security.fingerprint -cne (Effect-Security $item).fingerprint) { throw 'effect-identity' }
  return @{device=$after.device;inode=$after.inode;contentBase64=[Convert]::ToBase64String($bytes)}
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
  $script:phase = 'effect-rename'
  if ($item.closed -or $parent.closed -or $item.directory -or !$parent.directory -or
      $null -eq $item.parent -or $item.parent.handle -ne $parent.handle -or
      [IO.Path]::GetDirectoryName([string]$item.path) -cne [string]$parent.path -or
      $name.Length -eq 0 -or $name -match '[\\/:]' -or $name -in @('.', '..')) { throw 'effect-path' }
  $bytes = [Text.Encoding]::Unicode.GetBytes($name)
  $nameOffset = 2 * [IntPtr]::Size + 4
  $structureSize = [int]([Math]::Ceiling(($nameOffset + 2) / [double][IntPtr]::Size) * [IntPtr]::Size)
  $bufferSize = $structureSize + $bytes.Length
  $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
  $statusBlock = [Runtime.InteropServices.Marshal]::AllocHGlobal(2 * [IntPtr]::Size)
  try {
    for ($index = 0; $index -lt $bufferSize; $index++) { [Runtime.InteropServices.Marshal]::WriteByte($buffer, $index, 0) }
    # Native same-directory rename is relative to the held source object.
    # RootDirectory stays NULL; ReplaceIfExists stays FALSE. A supplied root
    # invokes IopOpenLinkOrRenameTarget and conflicts with our write-denying pin.
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer, 2 * [IntPtr]::Size, $bytes.Length)
    [Runtime.InteropServices.Marshal]::Copy($bytes, 0, [IntPtr]::Add($buffer, $nameOffset), $bytes.Length)
    $status = $native::NtSetInformationFile($item.handle, $statusBlock, $buffer, $bufferSize, 10)
    if ($status -ne 0) { $script:nativeStatus = $status; throw 'effect-rename' }
    $item.path = [IO.Path]::Combine($parent.path, $name)
  } finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($statusBlock)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
  }
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
  $content = Effect-Read $item 4096
  if (!(Effect-SameIdentity (Effect-Info $item.handle) $lease) -or (Effect-HashBytes $content) -cne [string]$lease.digest) { throw 'writer-lease' }
  Check-WriterLeaseProcess $lease $content
  return $item
}

function Effect-AbsentProcess([int]$processId) {
  Assert-ProcessAbsent $processId
}

function Invoke-MissionSpecPublication($context, $operation) {
  if ([string]$operation.kind -notin @('publish', 'inspect-publication')) { throw 'effect-operation' }
  if ($null -eq $operation.lease -and $operation.kind -ceq 'publish') { throw 'writer-lease' }
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
  # An unprepared publication need not have destination parents yet. Inspection
  # never creates them; mutation/recovery still require the pinned parent below.
  $parent = Effect-PinDirectory $context ([IO.Path]::GetDirectoryName([string]$operation.path))
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
    readOnly=([string]$operation.kind -cin @('read', 'sqlite-header'))
    sqliteHeader=([string]$operation.kind -ceq 'sqlite-header')
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
      'read' {
        return Invoke-EffectRead $context $operation
      }
      'sqlite-header' {
        return Invoke-EffectRead $context $operation
      }
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
        if ($null -ne $operation.absentInstance) {
          if ($null -ne $operation.absentProcess) { throw 'process-instance' }
          $owner = [Text.UTF8Encoding]::new($false, $true).GetString((Effect-Read $item 4096)) | Microsoft.PowerShell.Utility\ConvertFrom-Json
          if (!(Check-WriterLock $owner)) { throw 'writer-lease' }
          Check-ProcessInstance $owner.process
          Check-ProcessInstance $operation.absentInstance
          if ($owner.schemaVersion -ne 2 -or $owner.pid -ne $owner.process.pid -or
              $owner.process.pid -ne $operation.absentInstance.pid -or
              $owner.process.creationFileTime -cne $operation.absentInstance.creationFileTime) { throw 'writer-lease' }
          Check-WriterProcess $operation.absentInstance $true
        }
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

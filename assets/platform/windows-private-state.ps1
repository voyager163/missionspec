$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)
$phase = 'input'
$boundary = 'helper'
$leaseHandle = [IntPtr]::Zero
try {
  if (![string]::Equals([Environment]::SystemDirectory, 'C:\Windows\System32', [StringComparison]::OrdinalIgnoreCase) -or
      ![string]::Equals($PSHOME, 'C:\Windows\System32\WindowsPowerShell\v1.0', [StringComparison]::OrdinalIgnoreCase) -or
      ![string]::Equals([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName,
        'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', [StringComparison]::OrdinalIgnoreCase)) { throw 'system-executable' }
  $phase = 'access-policy'
  . ($PSScriptRoot + '\windows-access-policy.ps1')
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $osTrusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  $trusted = @($sid) + $osTrusted
  $phase = 'native-bindings'
  $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
    [Reflection.AssemblyName]::new('MissionSpec.WindowsState'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
  $type = $assembly.DefineDynamicModule('Native').DefineType('Native', 'Public, Sealed, Abstract')
  function Native($name, $dll, $result, [Type[]]$parameters) {
    $method = $type.DefinePInvokeMethod($name, $dll, 'Public, Static, PinvokeImpl',
      [Reflection.CallingConventions]::Standard, $result, $parameters,
      [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $attribute = [Runtime.InteropServices.DllImportAttribute]
    $method.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new(
      $attribute.GetConstructor([Type[]]@([string])), [object[]]@($dll),
      [Reflection.FieldInfo[]]@($attribute.GetField('SetLastError'), $attribute.GetField('CharSet'), $attribute.GetField('ExactSpelling')),
      [object[]]@($true, [Runtime.InteropServices.CharSet]::Unicode, $true)))
  }
  Native 'GetDriveTypeW' 'kernel32.dll' ([uint32]) @([string])
  Native 'GetVolumeInformationW' 'kernel32.dll' ([bool]) @([string], [IntPtr], [uint32], [IntPtr], [IntPtr], [uint32].MakeByRefType(), [IntPtr], [uint32])
  Native 'QueryDosDeviceW' 'kernel32.dll' ([uint32]) @([string], [Text.StringBuilder], [uint32])
  Native 'CreateFileW' 'kernel32.dll' ([IntPtr]) @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])
  Native 'GetFinalPathNameByHandleW' 'kernel32.dll' ([uint32]) @([IntPtr], [Text.StringBuilder], [uint32], [uint32])
  Native 'GetFileInformationByHandle' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr])
  Native 'GetFileInformationByHandleEx' 'kernel32.dll' ([bool]) @([IntPtr], [int], [IntPtr], [uint32])
  Native 'FlushFileBuffers' 'kernel32.dll' ([bool]) @([IntPtr])
  Native 'K32EnumProcesses' 'kernel32.dll' ([bool]) @([IntPtr], [uint32], [uint32].MakeByRefType())
  Native 'CloseHandle' 'kernel32.dll' ([bool]) @([IntPtr])
  Native 'CreateDirectoryW' 'kernel32.dll' ([bool]) @([string], [IntPtr])
  Native 'LocalFree' 'kernel32.dll' ([IntPtr]) @([IntPtr])
  Native 'ConvertStringSecurityDescriptorToSecurityDescriptorW' 'advapi32.dll' ([bool]) @([string], [uint32], [IntPtr].MakeByRefType(), [uint32].MakeByRefType())
  Native 'GetSecurityInfo' 'advapi32.dll' ([uint32]) @([IntPtr], [int], [uint32], [IntPtr], [IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())
  Native 'GetSecurityDescriptorLength' 'advapi32.dll' ([uint32]) @([IntPtr])
  $native = $type.CreateType()
  function CheckDirectoryIdentity([IntPtr]$information, $expected, [bool]$directory = $true) {
    $bytes = [byte[]]::new(52)
    [Runtime.InteropServices.Marshal]::Copy($information, $bytes, 0, 52)
    $attributes = [BitConverter]::ToUInt32($bytes, 0)
    $device = [BitConverter]::ToUInt32($bytes, 28)
    $inode = [decimal]([BitConverter]::ToUInt32($bytes, 44)) * 4294967296 +
      [decimal]([BitConverter]::ToUInt32($bytes, 48))
    $kind = if ($directory) { 0x10 } else { 0 }
    if (($attributes -band 0x410) -ne $kind -or
        $device.ToString([Globalization.CultureInfo]::InvariantCulture) -cne [string]$expected.device -or
        $inode.ToString('0', [Globalization.CultureInfo]::InvariantCulture) -cne [string]$expected.inode) { throw 'directory-identity' }
  }
  function FileSecurity([string]$p) {
    $sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
    return [IO.File]::GetAccessControl($p, $sections).GetSecurityDescriptorSddlForm($sections)
  }
  function FilePolicy([string]$p) {
    $handle = $native::CreateFileW($p, 0x20080, 7, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'file-security' }
    $descriptor = [IntPtr]::Zero
    $label = [IntPtr]::Zero
    try {
      # Access-affecting labels, attributes, scope and filters; not privileged audit-SACL access.
      if ($native::GetSecurityInfo($handle, 1, 0x1F0, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
          [ref]$label, [ref]$descriptor) -ne 0) { throw 'file-security' }
      $length = $native::GetSecurityDescriptorLength($descriptor)
      if ($length -lt 20 -or $length -gt 8192) { throw 'file-security' }
      $bytes = [byte[]]::new($length)
      [Runtime.InteropServices.Marshal]::Copy($descriptor, $bytes, 0, $length)
      $security = [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
      return $security.GetSddlForm([Security.AccessControl.AccessControlSections]::Audit)
    } finally {
      [void]$native::LocalFree($descriptor)
      if (!$native::CloseHandle($handle)) { throw 'close' }
    }
  }
  function CheckEntry([string]$p, [bool]$private, [bool]$directory, [bool]$writable, [bool]$system = $false, $flushExpected = $null, [bool]$ordinary = $false) {
    $script:boundary = if ($system) { 'system' } elseif ($private) { 'private' } else { 'ancestor' }
    $script:phase = 'entry-open'
    $entryTrusted = if ($system) { $osTrusted } else { $trusted }
    $flushRequested = $null -ne $flushExpected
    $access = if ($flushRequested) { 0x40020080 } else { 0x20080 }
    $sharing = if ($flushRequested) { 3 } else { 7 }
    $handle = $native::CreateFileW($p, $access, $sharing, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'open' }
    $info = [IntPtr]::Zero
    try {
      $info = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
      $script:phase = 'entry-information'
      if (!$native::GetFileInformationByHandle($handle, $info)) { throw 'identity' }
      $script:phase = 'entry-attributes'
      $attributes = [Runtime.InteropServices.Marshal]::ReadInt32($info, 0)
      if (($attributes -band 0x400) -ne 0 -or (($attributes -band 0x10) -ne 0) -ne $directory) { throw 'type' }
      if ($private -and !$directory -and [Runtime.InteropServices.Marshal]::ReadInt32($info, 40) -ne 1) { throw 'links' }
      $final = [Text.StringBuilder]::new(1024)
      $script:phase = 'entry-final-path'
      $length = $native::GetFinalPathNameByHandleW($handle, $final, 1024, 0)
      if ($length -eq 0 -or $length -ge 1024 -or ![string]::Equals($final.ToString(), ('\\?\' + $p), [StringComparison]::Ordinal)) { throw 'alias' }
      $sections = [Security.AccessControl.AccessControlSections]'Owner, Access'
      $script:phase = 'entry-acl-read'
      $acl = if ($directory) { [IO.Directory]::GetAccessControl($p, $sections) } else { [IO.File]::GetAccessControl($p, $sections) }
      $script:phase = 'entry-acl-parse'
      $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
      $script:phase = 'entry-owner'
      if ($null -eq $raw.DiscretionaryAcl -or $null -eq $raw.Owner) { throw 'acl' }
      if (($private -and $raw.Owner.Value -ne $sid) -or (!$private -and $raw.Owner.Value -notin $entryTrusted)) { throw 'owner' }
      $own = 0
      $inheritOnly = [int][Security.AccessControl.AceFlags]::InheritOnly
      $script:phase = 'entry-aces'
      foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { throw 'unsupported-ace' }
        $flags = [int]$ace.AceFlags
        if (($flags -band $inheritOnly) -ne 0) { continue }
        $principal = $ace.SecurityIdentifier.Value
        if ($principal -eq $sid) { $own = $own -bor $ace.AccessMask }
        if ($private -and $principal -notin @($sid, 'S-1-5-18', 'S-1-5-32-544')) { throw 'public-access' }
        if ($principal -notin $entryTrusted) {
          if ($private -or (Test-MissionSpecUntrustedMutation $ace.AccessMask $directory)) { throw 'public-access' }
        }
      }
      if ($private) {
        $script:phase = 'entry-user-access'
        $required = if ($writable) { 0x1F01FF } elseif ($directory) { 0x1200A9 } else { 0x120089 }
        if (($own -band $required) -ne $required) { throw 'user-access' }
        # New SQLite sidecars must not inherit a grant to another principal.
        if ($directory) {
          $script:phase = 'entry-inheritance'
          $inherit = 0
          foreach ($ace in $raw.DiscretionaryAcl) {
            $flags = [int]$ace.AceFlags
            if (($flags -band 3) -ne 0) {
              if ($ace.SecurityIdentifier.Value -notin @($sid, 'S-1-5-18', 'S-1-5-32-544') -or ($flags -band 4) -ne 0) { throw 'inheritance' }
              if ($ace.SecurityIdentifier.Value -eq $sid -and ($flags -band 3) -eq 3) { $inherit = $inherit -bor $ace.AccessMask }
            }
          }
          if ($ordinary) {
            $script:phase = 'file-metadata'
            if ($directory -or ($attributes -band (-bnot 0xA0)) -ne 0) { throw 'file-metadata' }
            $streams = [Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
            try {
              if (!$native::GetFileInformationByHandleEx($handle, 7, $streams, 1024) -or
                  [Runtime.InteropServices.Marshal]::ReadInt32($streams, 0) -ne 0 -or
                  [Runtime.InteropServices.Marshal]::ReadInt32($streams, 4) -ne 14 -or
                  [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]::Add($streams, 24), 7) -cne '::$DATA') { throw 'file-metadata' }
            } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($streams) }
          }
          if ($writable -and ($inherit -band 0x1F01FF) -ne 0x1F01FF) { throw 'inheritance' }
        }
      }
      if ($flushRequested) {
        $script:phase = 'directory-identity'
        if (!$private -or !$directory -or !$writable -or $system) { throw 'flush-options' }
        if (!$native::GetFileInformationByHandle($handle, $info)) { throw 'directory-identity' }
        CheckDirectoryIdentity $info $flushExpected
        $script:phase = 'directory-flush'
        if (!$native::FlushFileBuffers($handle)) { throw 'directory-flush' }
        $script:phase = 'directory-identity'
        if (!$native::GetFileInformationByHandle($handle, $info)) { throw 'directory-identity' }
        CheckDirectoryIdentity $info $flushExpected
        [void]$final.Clear()
        $length = $native::GetFinalPathNameByHandleW($handle, $final, 1024, 0)
        if ($length -eq 0 -or $length -ge 1024 -or ![string]::Equals($final.ToString(), ('\\?\' + $p), [StringComparison]::Ordinal)) {
          throw 'directory-identity'
        }
      }
    } finally {
      try {
        if ($info -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($info) }
      } finally {
        if (!$native::CloseHandle($handle)) {
          if ($flushRequested) { $script:phase = 'directory-close' }
          throw 'close'
        }
      }
    }
  }
  foreach ($osDirectory in @('C:\', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\System32\WindowsPowerShell',
      'C:\Windows\System32\WindowsPowerShell\v1.0')) { CheckEntry $osDirectory $false $true $false $true }
  CheckEntry 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' $false $false $false $true
  $phase = 'json-module'
  $boundary = 'helper'
  Import-Module -Name 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1' -ErrorAction Stop
  $phase = 'json-input'
  $inputObject = [Console]::In.ReadToEnd() | Microsoft.PowerShell.Utility\ConvertFrom-Json
  if ($null -ne $inputObject.lease) {
    $phase = 'writer-lease'
    $lease = $inputObject.lease
    $workspaceRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([string]$lease.path))
    if ([IO.Path]::GetFileName([string]$lease.path) -cne 'transaction.lock' -or
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName([string]$lease.path)) -cne '.missionspec') { throw 'writer-lease' }
    foreach ($entry in $inputObject.entries) {
      if ([string]$entry.path -cne $workspaceRoot -and
          !([string]$entry.path).StartsWith($workspaceRoot + '\', [StringComparison]::Ordinal)) { throw 'writer-lease' }
    }
    CheckEntry ([string]$lease.path) $true $false $true $false $null $true
    $phase = 'writer-lease'
    $leaseHandle = $native::CreateFileW([string]$lease.path, [uint32]2147614848, 3, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($leaseHandle -eq [IntPtr](-1)) { $leaseHandle = [IntPtr]::Zero; throw 'writer-lease' }
    $leaseInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
    try {
      if (!$native::GetFileInformationByHandle($leaseHandle, $leaseInfo)) { throw 'writer-lease' }
      CheckDirectoryIdentity $leaseInfo $lease $false
      if ([Runtime.InteropServices.Marshal]::ReadInt32($leaseInfo, 40) -ne 1) { throw 'writer-lease' }
      $safe = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($leaseHandle, $false)
      $stream = [IO.FileStream]::new($safe, [IO.FileAccess]::Read)
      $hash = [Security.Cryptography.SHA256]::Create()
      try {
        if ($stream.Length -gt 4096) { throw 'writer-lease' }
        $digest = 'sha256:' + [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
        if ($digest -cne [string]$lease.digest) { throw 'writer-lease' }
      } finally { $hash.Dispose(); $stream.Dispose(); $safe.Dispose() }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($leaseInfo) }
  }
  if ($null -ne $inputObject.absentProcess) {
    $phase = 'process-inspection'
    $processId = [int]$inputObject.absentProcess
    if ($processId -le 0) { throw 'process-inspection' }
    $processes = [Runtime.InteropServices.Marshal]::AllocHGlobal(65536)
    try {
      $count = [uint32]0
      if (!$native::K32EnumProcesses($processes, 65536, [ref]$count) -or $count -ge 65536 -or ($count % 4) -ne 0) { throw 'process-inspection' }
      $observedSelf = $false
      for ($index = 0; $index -lt $count; $index += 4) {
        $observed = [Runtime.InteropServices.Marshal]::ReadInt32($processes, $index)
        if ($observed -eq $PID) { $observedSelf = $true }
        if ($observed -eq $processId) { throw 'process-present' }
      }
      if (!$observedSelf) { throw 'process-inspection' }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($processes) }
  }
  foreach ($entry in $inputObject.entries) {
    if ($null -ne $entry.flushIdentity) {
      $phase = 'flush-options'
      if ($entry.directory -ne $true -or $entry.writable -ne $true -or $entry.create -or
          [string]$entry.flushIdentity.device -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or
          [decimal]$entry.flushIdentity.device -gt 4294967295 -or
          [string]$entry.flushIdentity.inode -cnotmatch '^[1-9][0-9]{0,19}$' -or
          [decimal]$entry.flushIdentity.inode -gt [decimal]'18446744073709551615') { throw 'flush-options' }
    }
    $phase = 'volume'
    $p = [string]$entry.path
    $drive = $p.Substring(0, 3)
    $device = [Text.StringBuilder]::new(1024)
    if ($native::GetDriveTypeW($drive) -ne 3 -or [IO.DriveInfo]::new($drive).DriveFormat -cne 'NTFS' -or
        $native::QueryDosDeviceW($drive.Substring(0, 2), $device, 1024) -eq 0 -or
        $device.ToString() -cnotmatch '^\\Device\\HarddiskVolume[0-9]+$') { throw 'volume' }
    if ($entry.ordinaryFile) {
      $filesystemFlags = [uint32]0
      if (!$native::GetVolumeInformationW($drive, [IntPtr]::Zero, 0, [IntPtr]::Zero, [IntPtr]::Zero,
          [ref]$filesystemFlags, [IntPtr]::Zero, 0) -or ($filesystemFlags -band 0x400) -eq 0) { throw 'file-metadata' }
    }
    $parent = [IO.Path]::GetDirectoryName($p)
    $ancestors = @($drive)
    $cursor = $drive.TrimEnd('\')
    foreach ($part in $parent.Substring(3).Split('\')) {
      if ($part.Length -ne 0) { $cursor += '\' + $part; $ancestors += $cursor }
    }
    foreach ($ancestor in $ancestors) { CheckEntry $ancestor $false $true $false }
    $security = $null
    $label = $null
    if ($null -ne $entry.copySecurityFrom -or $null -ne $entry.sameSecurityAs) {
      $phase = 'file-security'
      $template = if ($null -ne $entry.copySecurityFrom) { [string]$entry.copySecurityFrom } else { [string]$entry.sameSecurityAs }
      if ($entry.directory -or $template -ceq $p -or [IO.Path]::GetDirectoryName($template) -cne $parent -or
          ($null -ne $entry.copySecurityFrom -and !$entry.create)) { throw 'file-security' }
      CheckEntry $template $true $false $true $false $null $true
      $security = FileSecurity $template
      $label = FilePolicy $template
    }
    if ($entry.create) {
      $phase = 'creation'
      if ($entry.directory -eq $false) { CheckEntry $parent $true $true $true }
      $descriptor = [IntPtr]::Zero
      $size = [uint32]0
      $attributes = [Runtime.InteropServices.Marshal]::AllocHGlobal(3 * [IntPtr]::Size)
      try {
        $sddl = if ($null -ne $security) { $security } else { 'O:' + $sid + 'D:P(A;OICI;FA;;;' + $sid + ')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' }
        if (!$native::ConvertStringSecurityDescriptorToSecurityDescriptorW($sddl, 1, [ref]$descriptor, [ref]$size)) { throw 'descriptor' }
        [Runtime.InteropServices.Marshal]::WriteInt32($attributes, 0, 3 * [IntPtr]::Size)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($attributes, [IntPtr]::Size, $descriptor)
        [Runtime.InteropServices.Marshal]::WriteInt32($attributes, 2 * [IntPtr]::Size, 0)
        if ($entry.directory) {
          if (!$native::CreateDirectoryW($p, $attributes)) { throw 'create' }
        } else {
          $handle = $native::CreateFileW($p, 0x40000000, 7, $attributes, 1, 0x80, [IntPtr]::Zero)
          if ($handle -eq [IntPtr](-1)) { throw 'create' }
          if (!$native::CloseHandle($handle)) { throw 'close' }
        }
      } finally {
        [void]$native::LocalFree($descriptor)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($attributes)
      }
    }
    CheckEntry $p $true ([bool]$entry.directory) ([bool]$entry.writable) $false $entry.flushIdentity ([bool]$entry.ordinaryFile)
    if ($null -ne $security -and ((FileSecurity $p) -cne $security -or (FilePolicy $p) -cne $label)) { throw 'file-security' }
  }
  if ($leaseHandle -ne [IntPtr]::Zero) {
    $closing = $leaseHandle
    $leaseHandle = [IntPtr]::Zero
    if (!$native::CloseHandle($closing)) { throw 'lease-close' }
  }
  [Console]::Out.Write('{"ok":true}')
} catch {
  $failure = $_
  $reason = $_.Exception.Message
  if ($reason -notin @('system-executable','open','identity','type','links','alias','acl','owner','unsupported-ace','public-access',
      'user-access','inheritance','close','volume','descriptor','create','directory-identity','directory-flush','directory-close','flush-options',
      'file-metadata','file-security','process-inspection','process-present','writer-lease','lease-close')) { $reason = $phase }
  $knownTypes = @('RuntimeException', 'MethodException', 'MethodInvocationException', 'PSInvalidCastException',
    'ParameterBindingException', 'ArgumentException', 'ArgumentNullException', 'InvalidOperationException',
    'NotSupportedException', 'TypeLoadException', 'MissingMethodException', 'IOException', 'UnauthorizedAccessException',
    'FileNotFoundException', 'DirectoryNotFoundException', 'CmdletInvocationException', 'ActionPreferenceStopException')
  $exceptionType = $failure.Exception.GetType().Name
  if ($exceptionType -notin $knownTypes) { $exceptionType = 'other' }
  $innerType = 'none'
  if ($null -ne $failure.Exception.InnerException) {
    $innerType = $failure.Exception.InnerException.GetType().Name
    if ($innerType -notin $knownTypes) { $innerType = 'other' }
  }
  $line = [int]$failure.InvocationInfo.ScriptLineNumber
  [Console]::Out.Write('{"ok":false,"reason":"' + $reason + '","phase":"' + $phase +
    '","boundary":"' + $boundary + '","exceptionType":"' + $exceptionType + '","innerType":"' + $innerType + '","line":' + $line + '}')
  exit 1
} finally {
  if ($leaseHandle -ne [IntPtr]::Zero) {
    if (!$native::CloseHandle($leaseHandle)) { [Environment]::ExitCode = 1 }
  }
}

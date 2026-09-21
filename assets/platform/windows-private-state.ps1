$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)
$phase = 'input'
$boundary = 'helper'
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
  Native 'QueryDosDeviceW' 'kernel32.dll' ([uint32]) @([string], [Text.StringBuilder], [uint32])
  Native 'CreateFileW' 'kernel32.dll' ([IntPtr]) @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])
  Native 'GetFinalPathNameByHandleW' 'kernel32.dll' ([uint32]) @([IntPtr], [Text.StringBuilder], [uint32], [uint32])
  Native 'GetFileInformationByHandle' 'kernel32.dll' ([bool]) @([IntPtr], [IntPtr])
  Native 'CloseHandle' 'kernel32.dll' ([bool]) @([IntPtr])
  Native 'CreateDirectoryW' 'kernel32.dll' ([bool]) @([string], [IntPtr])
  Native 'LocalFree' 'kernel32.dll' ([IntPtr]) @([IntPtr])
  Native 'ConvertStringSecurityDescriptorToSecurityDescriptorW' 'advapi32.dll' ([bool]) @([string], [uint32], [IntPtr].MakeByRefType(), [uint32].MakeByRefType())
  $native = $type.CreateType()
  function CheckEntry([string]$p, [bool]$private, [bool]$directory, [bool]$writable, [bool]$system = $false) {
    $script:boundary = if ($system) { 'system' } elseif ($private) { 'private' } else { 'ancestor' }
    $script:phase = 'entry-open'
    $entryTrusted = if ($system) { $osTrusted } else { $trusted }
    $handle = $native::CreateFileW($p, 0x20080, 7, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'open' }
    $info = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
    try {
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
          if ($writable -and ($inherit -band 0x1F01FF) -ne 0x1F01FF) { throw 'inheritance' }
        }
      }
    } finally {
      [Runtime.InteropServices.Marshal]::FreeHGlobal($info)
      if (!$native::CloseHandle($handle)) { throw 'close' }
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
  foreach ($entry in $inputObject.entries) {
    $phase = 'volume'
    $p = [string]$entry.path
    $drive = $p.Substring(0, 3)
    $device = [Text.StringBuilder]::new(1024)
    if ($native::GetDriveTypeW($drive) -ne 3 -or [IO.DriveInfo]::new($drive).DriveFormat -cne 'NTFS' -or
        $native::QueryDosDeviceW($drive.Substring(0, 2), $device, 1024) -eq 0 -or
        $device.ToString() -cnotmatch '^\\Device\\HarddiskVolume[0-9]+$') { throw 'volume' }
    $parent = [IO.Path]::GetDirectoryName($p)
    $ancestors = @($drive)
    $cursor = $drive.TrimEnd('\')
    foreach ($part in $parent.Substring(3).Split('\')) {
      if ($part.Length -ne 0) { $cursor += '\' + $part; $ancestors += $cursor }
    }
    foreach ($ancestor in $ancestors) { CheckEntry $ancestor $false $true $false }
    if ($entry.create) {
      $phase = 'creation'
      if ($entry.directory -eq $false) { CheckEntry $parent $true $true $true }
      $descriptor = [IntPtr]::Zero
      $size = [uint32]0
      $attributes = [Runtime.InteropServices.Marshal]::AllocHGlobal(3 * [IntPtr]::Size)
      try {
        $sddl = 'O:' + $sid + 'D:P(A;OICI;FA;;;' + $sid + ')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
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
    CheckEntry $p $true ([bool]$entry.directory) ([bool]$entry.writable)
  }
  [Console]::Out.Write('{"ok":true}')
} catch {
  $failure = $_
  $reason = $_.Exception.Message
  if ($reason -notin @('system-executable','open','identity','type','links','alias','acl','owner','unsupported-ace','public-access',
      'user-access','inheritance','close','volume','descriptor','create')) { $reason = $phase }
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
}

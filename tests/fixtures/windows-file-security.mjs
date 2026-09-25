import { fileURLToPath } from 'node:url';
import { powershell } from './windows-private-state.mjs';

const policy = fileURLToPath(new URL('../../assets/platform/windows-access-policy.ps1', import.meta.url));

export function windowsFileSecurity(options) {
  return powershell(String.raw`
$ErrorActionPreference = 'Stop'
$v = [Console]::In.ReadToEnd() | ConvertFrom-Json
. $v.policy
$sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
$entry = if ($v.directory) { [IO.Directory] } else { [IO.File] }
$security = $entry::GetAccessControl($v.path, $sections)
if ($v.readOnly) {
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $security.SetAccessRuleProtection($true, $false)
  $security.PurgeAccessRules($sid)
  $inherit = if ($v.directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid, 'ReadAndExecute', $inherit, 'None', 'Allow'))
}
if ($v.removeSystem) {
  foreach ($rule in @($security.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
    if ($rule.IdentityReference.Value -eq 'S-1-5-18') { $security.RemoveAccessRuleSpecific($rule) }
  }
}
if ($v.publicRead) {
  $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Allow'))
}
if ($null -ne $v.restoreSddl) { $security.SetSecurityDescriptorSddlForm($v.restoreSddl, $sections) }
if ($v.removeSystem -or $v.publicRead -or $v.readOnly -or $null -ne $v.restoreSddl) { $entry::SetAccessControl($v.path, $security) }
$sddl = $entry::GetAccessControl($v.path, $sections).GetSecurityDescriptorSddlForm($sections)
$key = Get-MissionSpecFileSecurityKey $sddl
$hash = [Security.Cryptography.SHA256]::Create()
try { $fingerprint = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))).Replace('-', '').ToLowerInvariant() }
finally { $hash.Dispose() }
[Console]::Out.Write((@{sddl=$sddl;fingerprint=$fingerprint} | ConvertTo-Json -Compress))
`, { ...options, policy });
}

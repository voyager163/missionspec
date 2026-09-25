function Test-MissionSpecUntrustedMutation([int]$accessMask, [bool]$directory) {
  $forbidden = 0xD00D0150
  # Directory create-child rights are not file write/append rights.
  if (!$directory) { $forbidden = $forbidden -bor 0x6 }
  return ($accessMask -band $forbidden) -ne 0
}

function Get-MissionSpecFileSecurityDescriptor([string]$sddl) {
  $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
  $flags = [int]$descriptor.ControlFlags
  # AI records prior automatic inheritance, not a grant. With P set, further
  # inheritance is blocked; keep P, AR and every ACE/ACE flag unchanged.
  if (($flags -band 0x1000) -ne 0) {
    $descriptor.SetFlags([Security.AccessControl.ControlFlags]($flags -band (-bnot 0x400)))
  }
  return $descriptor
}

function Get-MissionSpecFileSecurityKey([string]$sddl) {
  $descriptor = Get-MissionSpecFileSecurityDescriptor $sddl
  $bytes = [byte[]]::new($descriptor.BinaryLength)
  $descriptor.GetBinaryForm($bytes, 0)
  return [Convert]::ToBase64String($bytes)
}

function Compare-MissionSpecFileSecurity([string]$expected, [string]$actual) {
  $left = Get-MissionSpecFileSecurityDescriptor $expected
  $right = Get-MissionSpecFileSecurityDescriptor $actual
  if ($left.Owner.Value -cne $right.Owner.Value) { return 'owner' }
  if ($left.Group.Value -cne $right.Group.Value) { return 'group' }
  if ([int]$left.ControlFlags -ne [int]$right.ControlFlags) { return 'control' }
  if (($null -eq $left.DiscretionaryAcl) -ne ($null -eq $right.DiscretionaryAcl)) { return 'dacl' }
  if ($null -ne $left.DiscretionaryAcl) {
    $leftBytes = [byte[]]::new($left.DiscretionaryAcl.BinaryLength)
    $rightBytes = [byte[]]::new($right.DiscretionaryAcl.BinaryLength)
    $left.DiscretionaryAcl.GetBinaryForm($leftBytes, 0)
    $right.DiscretionaryAcl.GetBinaryForm($rightBytes, 0)
    if ([Convert]::ToBase64String($leftBytes) -cne [Convert]::ToBase64String($rightBytes)) { return 'dacl' }
  }
  if ((Get-MissionSpecFileSecurityKey $expected) -cne (Get-MissionSpecFileSecurityKey $actual)) { return 'descriptor' }
  return 'equal'
}

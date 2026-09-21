function Test-MissionSpecUntrustedMutation([int]$accessMask, [bool]$directory) {
  $forbidden = 0xD00D0150
  # Directory create-child rights are not file write/append rights.
  if (!$directory) { $forbidden = $forbidden -bor 0x6 }
  return ($accessMask -band $forbidden) -ne 0
}

$phase = 'bootstrap'
try {
  . ($PSScriptRoot + '\..\..\assets\platform\windows-execution-native.ps1')
  try {
    $inputHandle = $native::GetStdHandle(-10)
    $outputHandle = $native::GetStdHandle(-12)
    $inputMode = [uint32]0
    $outputMode = [uint32]0
    $observation = @{
      inputType=$native::GetFileType($inputHandle); outputType=$native::GetFileType($outputHandle)
      inputConsole=$native::GetConsoleMode($inputHandle, [ref]$inputMode)
      outputConsole=$native::GetConsoleMode($outputHandle, [ref]$outputMode)
    }
    $observation.inputMode = $inputMode
    $observation.outputMode = $outputMode
  } finally { Release-Native }
  [Console]::Out.Write(($observation | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
} catch {
  [Console]::Out.Write(('WINDOWS_CONSOLE_FAILURE:{"stage":"stdio-probe","phase":"' + $phase +
    '","line":' + [int]$_.InvocationInfo.ScriptLineNumber + '}'))
  exit 1
}

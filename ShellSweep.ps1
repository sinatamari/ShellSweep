Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);   
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
        byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);  
    [DllImport("kernel32.dll")]
    public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint MEM_IMAGE = 0x20000;
}
"@
$peb_walk_sig = [byte[]]@(0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B)
$ldr_loop_sig = [byte[]]@(0x8B, 0x40, 0x0C, 0x8B, 0x58, 0x0C)
$pe_parse_sig = [byte[]]@(0xB9, 0x3C, 0x00, 0x00, 0x00)
$nop_sled_sig = [byte[]]@(0x90, 0x90, 0x90, 0x90)
function Test-MemoryPattern {
    param([byte[]]$Buffer, [byte[]]$Pattern)
    for ($i = 0; $i -le $Buffer.Length - $Pattern.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Buffer[$i + $j] -ne $Pattern[$j]) { $match = $false; break }
        }
        if ($match) { return $true }
    }
    return $false
}
function Get-EntropyScore {
    param([byte[]]$Data)
    $histogram = New-Object int[] 256
    foreach ($byte in $Data) { $histogram[$byte]++ }
    $entropy = 0.0
    $total = $Data.Length
    foreach ($count in $histogram) {
        if ($count -gt 0) {
            $p = $count / $total
            $entropy -= $p * [Math]::Log($p, 2)
        }
    }
    return [math]::Round($entropy, 2)
}
function Dump-Hex {
    param([byte[]]$Data, [IntPtr]$BaseAddr, [int]$Size = 256)
    Write-Host "Hex dump at 0x$($BaseAddr.ToString('X16')) ($Size bytes):" -ForegroundColor Yellow
    for ($i = 0; $i -lt [Math]::Min($Size, $Data.Length); $i += 16) {
        $line = "{0:X4}: " -f $i
        for ($j = 0; $j -lt 16 -and ($i + $j) -lt $Size -and ($i + $j) -lt $Data.Length; $j++) {
            $line += "{0:X2} " -f $Data[$i + $j]
        }
        Write-Host $line
    }
    Write-Host ""
}
function Scan-ProcessMemory {
    param([int]$ProcessID, [string]$ProcessName)   
    $hProcess = [Win32]::OpenProcess(([Win32]::PROCESS_VM_READ -bor [Win32]::PROCESS_QUERY_INFORMATION), $false, $ProcessID)
    if ($hProcess -eq [IntPtr]::Zero) { return 0 }    
    $suspiciousCount = 0
    $mbi = New-Object Win32+MEMORY_BASIC_INFORMATION
    $addr = [IntPtr]::Zero
    $buffer = New-Object byte[] 4096  
    Write-Host "  Scanning PID $ProcessID ($ProcessName)..." -ForegroundColor Gray
    while ([Win32]::VirtualQueryEx($hProcess, $addr, [ref]$mbi, [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($mbi))) {
        # FIXED: Explicit casting to avoid unsigned/signed comparison issues
        if ([int]$mbi.State -eq [int][Win32]::MEM_COMMIT -and [long]$mbi.RegionSize.ToInt64() -gt 4096) {
            $protect = $mbi.Protect
            if (($protect -band [Win32]::PAGE_EXECUTE_READWRITE) -or 
                (($protect -band [Win32]::PAGE_EXECUTE_READ) -and [int]$mbi.Type -ne [int][Win32]::MEM_IMAGE)) {                
                $bytesRead = 0
                [Win32]::ReadProcessMemory($hProcess, $mbi.BaseAddress, $buffer, [Math]::Min(4096, [int]$mbi.RegionSize.ToInt64()), [ref]$bytesRead) | Out-Null                
                if ($bytesRead -gt 0) {
                    $score = 0
                    $hits = @()                    
                    if (Test-MemoryPattern $buffer[0..($bytesRead-1)] $peb_walk_sig) { $score += 3; $hits += "PEB" }
                    if (Test-MemoryPattern $buffer[0..($bytesRead-1)] $ldr_loop_sig) { $score += 3; $hits += "LDR" }
                    if (Test-MemoryPattern $buffer[0..($bytesRead-1)] $pe_parse_sig) { $score += 2; $hits += "PE" }
                    if (Test-MemoryPattern $buffer[0..($bytesRead-1)] $nop_sled_sig) { $score += 1; $hits += "NOP" }                    
                    $entropy = Get-EntropyScore $buffer[0..($bytesRead-1)]
                    if ($entropy -gt 7.2) { $score += 2; $hits += "Entropy($([math]::Round($entropy,1)))" }                    
                    if ($score -ge 6) {
                        Write-Host "  *** ALERT: PID $ProcessID ($ProcessName) ***" -ForegroundColor Red
                        Write-Host "    Region: 0x$($mbi.BaseAddress.ToString('X16')) (size: 0x$( '{0:X}' -f $mbi.RegionSize.ToInt64() ))" -ForegroundColor Red
                        Write-Host "    Score: $score/11 Hits: $($hits -join ', ')" -ForegroundColor Red
                        Dump-Hex $buffer $mbi.BaseAddress $bytesRead
                        $suspiciousCount++
                    }
                }
            }
        }
        $addr = [IntPtr]($mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64())
    }    
    [Win32]::CloseHandle($hProcess) | Out-Null
    return $suspiciousCount
}
Write-Host "=== SYSTEM-WIDE SHELLCODE HUNTER ===" -ForegroundColor Cyan
Write-Host "Scanning ALL running processes for shellcode injection..." -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
$totalProcesses = 0
$totalSuspicious = 0
$startTime = Get-Date
Get-Process | ForEach-Object {
    $totalProcesses++
    $suspCount = Scan-ProcessMemory -ProcessID $_.Id -ProcessName $_.ProcessName
    $totalSuspicious += $suspCount
    if ($totalProcesses % 50 -eq 0) {
        $elapsed = (Get-Date) - $startTime
        Write-Host "Processed $totalProcesses processes... ($([math]::Round($elapsed.TotalSeconds,1))s)" -ForegroundColor Green
    }
}
$elapsed = (Get-Date) - $startTime
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCAN COMPLETE!" -ForegroundColor Green
Write-Host "Total processes scanned: $totalProcesses" -ForegroundColor White
Write-Host "Suspicious regions found: $totalSuspicious" -ForegroundColor $(if($totalSuspicious -gt 0){'Red'}else{'Green'})
Write-Host "Scan time: $([math]::Round($elapsed.TotalSeconds,1)) seconds" -ForegroundColor White
if ($totalSuspicious -eq 0) {
    Write-Host "No shellcode detected." -ForegroundColor Green
} else {
    Write-Host "INVESTIGATE the flagged processes immediately!" -ForegroundColor Red
}
Write-Host "`nPress Enter to exit..." -ForegroundColor Gray
$null = Read-Host


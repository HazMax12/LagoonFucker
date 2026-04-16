
$WEBHOOK_URL = "https://discord.com/api/webhooks/1482121926309576775/byOjiXabKSC5HdvOBwfQlqjTR3CBfjPkEud775NlfjNlK72zSCu7hruPWWLVnnQTcVpR"
$SIG_URL = 'https://round-wood-10c4.zachriley1918.workers.dev/?token=LAGOONBREAKER'

$AC_CHUNK_SIZE = 25000

$SIG_FILE = [System.IO.Path]::Combine($env:TEMP, "lagoon_" + [System.IO.Path]::GetRandomFileName() + ".tmp")

function Remove-SigFile {
    if (Test-Path $SIG_FILE) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($SIG_FILE)
            [Array]::Clear($bytes, 0, $bytes.Length)
            [System.IO.File]::WriteAllBytes($SIG_FILE, $bytes)
        } catch { }
        Remove-Item -Path $SIG_FILE -Force -ErrorAction SilentlyContinue
    }
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Remove-SigFile } | Out-Null
try {
    [System.Console]::add_CancelKeyPress({
        param($s, $e); $e.Cancel = $true; Remove-SigFile; [System.Environment]::Exit(0)
    })
} catch { }

Add-Type @"
using System;
using System.IO;
using System.Runtime.InteropServices;
public class ProcessExitGuard {
    private static string _path;
    [DllImport("kernel32.dll")] private static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate h, bool add);
    private delegate bool ConsoleCtrlDelegate(uint sig);
    private static ConsoleCtrlDelegate _handler;
    public static void Register(string p) {
        _path = p; _handler = new ConsoleCtrlDelegate(HandleCtrl);
        SetConsoleCtrlHandler(_handler, true);
        AppDomain.CurrentDomain.ProcessExit        += (s,e) => Cleanup();
        AppDomain.CurrentDomain.UnhandledException += (s,e) => Cleanup();
    }
    private static bool HandleCtrl(uint sig) { Cleanup(); return false; }
    public static void Cleanup() {
        try { if (File.Exists(_path)) { var b=File.ReadAllBytes(_path); Array.Clear(b,0,b.Length); File.WriteAllBytes(_path,b); File.Delete(_path); } } catch {}
    }
}
"@
[ProcessExitGuard]::Register($SIG_FILE)

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public class MemScanner {

    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a, bool b, int c);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int sz, out int read);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, int sz);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    public const int PROCESS_VM_READ = 0x0010, PROCESS_QUERY_INFO = 0x0400;
    public const uint MEM_COMMIT = 0x1000, PAGE_READABLE = 0x02|0x04|0x20|0x40|0x80;
    public const int MIN_REGION = 64, MAX_REGION = 104857600;

    private class AhoCorasick {
        private readonly int[][] _goto;
        private readonly bool[]  _out;
        private readonly string[]_sig;
        public AhoCorasick(IEnumerable<KeyValuePair<byte[],string>> patterns) {
            var nodes=new List<int[]>(); var acc=new List<bool>(); var sig=new List<string>();
            nodes.Add(new int[256]); acc.Add(false); sig.Add(null);
            foreach(var kv in patterns){
                if(kv.Key==null||kv.Key.Length<4) continue;
                int cur=0;
                foreach(byte b in kv.Key){
                    if(nodes[cur][b]==0){ nodes[cur][b]=nodes.Count; nodes.Add(new int[256]); acc.Add(false); sig.Add(null); }
                    cur=nodes[cur][b];
                }
                acc[cur]=true; sig[cur]=kv.Value;
            }
            int sz=nodes.Count; var fail=new int[sz];
            _out=acc.ToArray(); _goto=nodes.ToArray(); _sig=sig.ToArray();
            var q=new Queue<int>();
            for(int c=0;c<256;c++){ int s=_goto[0][c]; if(s!=0){fail[s]=0;q.Enqueue(s);} }
            while(q.Count>0){
                int r=q.Dequeue();
                for(int c=0;c<256;c++){
                    int s=_goto[r][c];
                    if(s==0){ _goto[r][c]=_goto[fail[r]][c]; continue; }
                    q.Enqueue(s);
                    int f=fail[r]; while(f!=0&&_goto[f][c]==0) f=fail[f];
                    fail[s]=_goto[f][c]; if(fail[s]==s) fail[s]=0;
                    if(_out[fail[s]]&&_sig[s]==null) _sig[s]=_sig[fail[s]];
                    _out[s]=_out[s]||_out[fail[s]];
                }
            }
        }
        public void SearchAll(byte[] text, int len, HashSet<string> found){
            int state=0;
            for(int i=0;i<len;i++){
                state=_goto[state][text[i]];
                if(_out[state]&&_sig[state]!=null) found.Add(_sig[state]);
            }
        }
    }

    private static AhoCorasick[] _chunksAscii;
    private static AhoCorasick[] _chunksUnicode;

    public static int BuildProgress = 0;

    public static void BuildAutomataChunked(string[] sigs, int chunkSize){
        BuildProgress = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var unique = new List<string>();
        foreach(var s in sigs){ if(!string.IsNullOrEmpty(s)&&seen.Add(s)) unique.Add(s); }

        int total = unique.Count;
        if(total==0){ _chunksAscii=new AhoCorasick[0]; _chunksUnicode=new AhoCorasick[0]; return; }

        int numChunks = (total + chunkSize - 1) / chunkSize;
        _chunksAscii   = new AhoCorasick[numChunks];
        _chunksUnicode = new AhoCorasick[numChunks];

        int built = 0;
        Parallel.For(0, numChunks, new ParallelOptions{ MaxDegreeOfParallelism=Environment.ProcessorCount }, i => {
            int start = i * chunkSize;
            int end   = Math.Min(start + chunkSize, total);
            var ascii   = new List<KeyValuePair<byte[],string>>(end-start);
            var unicode = new List<KeyValuePair<byte[],string>>(end-start);
            for(int j=start;j<end;j++){
                string s = unique[j];
                ascii.Add(new KeyValuePair<byte[],string>(Encoding.ASCII.GetBytes(s), s));
                unicode.Add(new KeyValuePair<byte[],string>(Encoding.Unicode.GetBytes(s), s));
            }
            _chunksAscii[i]   = new AhoCorasick(ascii);
            _chunksUnicode[i] = new AhoCorasick(unicode);
            int b = Interlocked.Increment(ref built);
            BuildProgress = (int)((double)b / numChunks * 100);
        });
        BuildProgress = 100;
    }

    public static int ScanRegionsDone  = 0;
    public static int ScanRegionsTotal = 0;

    public static string[] ScanForAllMatches(int pid){
        if(_chunksAscii==null||_chunksAscii.Length==0) return new string[0];
        ScanRegionsDone = 0; ScanRegionsTotal = 0;

        IntPtr hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFO, false, pid);
        if(hProcess==IntPtr.Zero) return new string[0];
        try {
            var regions = new List<Tuple<IntPtr,int>>();
            IntPtr addr = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION mbi;
            int mbiSz = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            while(VirtualQueryEx(hProcess, addr, out mbi, mbiSz)!=0){
                long rs = mbi.RegionSize.ToInt64();
                if(mbi.State==MEM_COMMIT&&(mbi.Protect&PAGE_READABLE)!=0&&rs>=MIN_REGION&&rs<=MAX_REGION)
                    regions.Add(Tuple.Create(mbi.BaseAddress,(int)rs));
                long next = addr.ToInt64()+rs;
                if(next<=0||next<=addr.ToInt64()) break;
                addr = new IntPtr(next);
            }
            ScanRegionsTotal = regions.Count;

            var globalFound = new HashSet<string>(StringComparer.Ordinal);
            var locker = new object();

            Parallel.ForEach(regions, new ParallelOptions{ MaxDegreeOfParallelism=Environment.ProcessorCount }, (region,state) => {
                byte[] buf = new byte[region.Item2]; int bytesRead;
                if(!ReadProcessMemory(hProcess, region.Item1, buf, buf.Length, out bytesRead)||bytesRead<=0){
                    Interlocked.Increment(ref ScanRegionsDone); return;
                }
                var localFound = new HashSet<string>(StringComparer.Ordinal);
                foreach(var ac in _chunksAscii)   ac.SearchAll(buf, bytesRead, localFound);
                foreach(var ac in _chunksUnicode) ac.SearchAll(buf, bytesRead, localFound);
                if(localFound.Count>0){ lock(locker){ foreach(var s in localFound) globalFound.Add(s); } }
                Interlocked.Increment(ref ScanRegionsDone);
            });

            var result = new string[globalFound.Count]; globalFound.CopyTo(result); return result;
        } finally { CloseHandle(hProcess); }
    }
}
"@

function Show-ProgressBar {
    param([string]$Label,[int]$Percent,[int]$BarWidth=40)
    $filled = [int]([Math]::Round($Percent / 100.0 * $BarWidth))
    $empty  = $BarWidth - $filled
    $bar    = ('█' * $filled) + ('░' * $empty)
    Write-Host "`r  $Label  [$bar] $($Percent.ToString().PadLeft(3))%" -NoNewline -ForegroundColor Cyan
}

function Wait-WithBar {
    param([string]$Label,[scriptblock]$GetPct,[int]$BarWidth=40)
    while ($true) {
        $pct = & $GetPct
        Show-ProgressBar -Label $Label -Percent $pct -BarWidth $BarWidth
        if ($pct -ge 100) { break }
        Start-Sleep -Milliseconds 80
    }
    Write-Host ""
}

function Get-UsernameFromPid {
    param([int]$ProcessId)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        $cmd  = $proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
        if ($cmd -match '--username\s+"([^"]+)"') { return $matches[1] }
        if ($cmd -match '--username\s+(\S+)')     { return $matches[1] }
    } catch { }
    return $null
}

function Send-DiscordWebhook {
    param([string]$WebhookUrl,[string]$MinecraftUsername,[bool]$Detected,[int]$SigCount,[string[]]$ScannedPids)
    if ([string]::IsNullOrWhiteSpace($WebhookUrl) -or $WebhookUrl -like "*YOUR*") {
        Write-Host "  [!] Webhook URL not configured — skipping." -ForegroundColor DarkYellow; return
    }
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $pidList   = if ($ScannedPids.Count -gt 0) { $ScannedPids -join ", " } else { "None" }
    if ($Detected) { $color=15158332; $title=":warning: Cheat Client DETECTED"; $desc="**Lagoon Fucker** signatures found in memory." }
    else           { $color=3066993;  $title=":white_check_mark: Scan Clean";    $desc="No cheat signatures found in memory." }
    $payload = [ordered]@{ embeds = @([ordered]@{
        title=$title; description=$desc; color=$color
        fields=@(
            [ordered]@{ name="Minecraft Username"; value="``$MinecraftUsername``"; inline=$true  }
            [ordered]@{ name="Machine";            value="``$env:COMPUTERNAME``";  inline=$true  }
            [ordered]@{ name="Scanned PID(s)";     value="``$pidList``";           inline=$true  }
            [ordered]@{ name="Signatures Matched"; value="``$SigCount``";          inline=$true  }
            [ordered]@{ name="Scan Time (UTC)";    value="``$timestamp``";         inline=$false }
        )
        footer=[ordered]@{ text="Lagoon Fucker Detector by Ily_Mildy" }; timestamp=$timestamp
    })}
    $body = $payload | ConvertTo-Json -Depth 8 -Compress
    try { Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType "application/json" | Out-Null } catch { }
}

Clear-Host
Write-Host ""
Write-Host "  ██╗      █████╗  ██████╗  ██████╗  ██████╗ ███╗   ██╗" -ForegroundColor DarkRed
Write-Host "  ██║     ██╔══██╗██╔════╝ ██╔═══██╗██╔═══██╗████╗  ██║" -ForegroundColor Red
Write-Host "  ██║     ███████║██║  ███╗██║   ██║██║   ██║██╔██╗ ██║" -ForegroundColor Red
Write-Host "  ██║     ██╔══██║██║   ██║██║   ██║██║   ██║██║╚██╗██║" -ForegroundColor DarkRed
Write-Host "  ███████╗██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║" -ForegroundColor DarkRed
Write-Host "  ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝" -ForegroundColor DarkRed
Write-Host "  ███████╗██╗   ██╗ ██████╗██╗  ██╗███████╗██████╗ " -ForegroundColor DarkRed
Write-Host "  ██╔════╝██║   ██║██╔════╝██║ ██╔╝██╔════╝██╔══██╗" -ForegroundColor Red
Write-Host "  █████╗  ██║   ██║██║     █████╔╝ █████╗  ██████╔╝" -ForegroundColor Red
Write-Host "  ██╔══╝  ██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗" -ForegroundColor DarkRed
Write-Host "  ██║     ╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║" -ForegroundColor DarkRed
Write-Host "  ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝" -ForegroundColor DarkRed
Write-Host ""
Write-Host "  [ Lagoon Fucker | Version 1.2 | Made By Ily_Mildy ]" -ForegroundColor Cyan
Write-Host "  [ github.com/HazMax12/LagoonFucker ]" -ForegroundColor DarkCyan
Write-Host ("-" * 65) -ForegroundColor DarkGray
Write-Host ""

try {
    Write-Host "  [*] Fetching signature list..." -ForegroundColor DarkCyan
    try {
        $rawText   = Invoke-RestMethod -Uri $SIG_URL
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($SIG_FILE, $rawText, $utf8NoBom)
        Write-Host "  [+] Signatures fetched OK" -ForegroundColor DarkGreen
    } catch {
        Write-Host "  [!] Failed to fetch signatures: $_" -ForegroundColor Red
        exit 1
    }

    $SIGNATURES = [System.Collections.Generic.List[string]]::new()
    foreach ($line in [System.IO.File]::ReadAllLines($SIG_FILE, [System.Text.Encoding]::UTF8)) {
        $t = $line.Trim()
        if ($t.Length -gt 0 -and -not $t.StartsWith('#')) { $SIGNATURES.Add($t) }
    }
    Write-Host "  [*] Loaded $($SIGNATURES.Count) signatures" -ForegroundColor DarkCyan

    $javawProcs = Get-Process -Name "javaw" -ErrorAction SilentlyContinue
    if ($null -eq $javawProcs -or $javawProcs.Count -eq 0) {
        Write-Host ""
        Write-Host "  [!] No javaw.exe process found." -ForegroundColor Yellow
        Write-Host "      Make sure Minecraft is running before scanning." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Press Enter to exit..." -ForegroundColor DarkGray
        Read-Host | Out-Null
        exit
    }

    Write-Host ""
    Write-Host "  [*] Building Aho-Corasick automata (chunk size: $AC_CHUNK_SIZE)..." -ForegroundColor DarkCyan

    $numChunks = [int][Math]::Ceiling($SIGNATURES.Count / $AC_CHUNK_SIZE)
    Write-Host "  [*] $($SIGNATURES.Count) sigs → $numChunks chunk(s)" -ForegroundColor DarkGray

    $buildSw   = [System.Diagnostics.Stopwatch]::StartNew()

    $rs = [RunspaceFactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('sigs',  $SIGNATURES.ToArray())
    $rs.SessionStateProxy.SetVariable('chunk', $AC_CHUNK_SIZE)
    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    $ps.AddScript({
        [MemScanner]::BuildAutomataChunked($sigs, $chunk)
    }) | Out-Null
    $handle = $ps.BeginInvoke()

    Write-Host ""
    while (-not $handle.IsCompleted) {
        $pct = [MemScanner]::BuildProgress
        Show-ProgressBar -Label "  Building" -Percent $pct -BarWidth 40
        Start-Sleep -Milliseconds 80
    }
    Show-ProgressBar -Label "  Building" -Percent 100 -BarWidth 40
    Write-Host ""

    $ps.EndInvoke($handle) | Out-Null
    $ps.Dispose(); $rs.Close(); $rs.Dispose()
    $buildSw.Stop()
    Write-Host "  [+] Automata built in $($buildSw.ElapsedMilliseconds) ms" -ForegroundColor DarkGreen
    Write-Host ""

    $allMatchedSigs = [System.Collections.Generic.HashSet[string]]::new()
    $scannedPids    = @()
    $mcUsername     = "Unknown"

    foreach ($proc in $javawProcs) {
        $instanceUser = Get-UsernameFromPid -ProcessId $proc.Id
        if ($instanceUser) { $mcUsername = $instanceUser }

        Write-Host "  [*] Scanning javaw.exe  PID: $($proc.Id) ..." -ForegroundColor Cyan
        [MemScanner]::ScanRegionsDone  = 0
        [MemScanner]::ScanRegionsTotal = 0

        $scanSw = [System.Diagnostics.Stopwatch]::StartNew()

        $rs2 = [RunspaceFactory]::CreateRunspace()
        $rs2.Open()
        $rs2.SessionStateProxy.SetVariable('pid2', $proc.Id)
        $ps2 = [PowerShell]::Create()
        $ps2.Runspace = $rs2
        $ps2.AddScript({
            [MemScanner]::ScanForAllMatches($pid2)
        }) | Out-Null
        $handle2 = $ps2.BeginInvoke()

        Write-Host ""
        while (-not $handle2.IsCompleted) {
            $done  = [MemScanner]::ScanRegionsDone
            $total = [MemScanner]::ScanRegionsTotal
            $pct   = if ($total -gt 0) { [int]([Math]::Min(100, $done * 100 / $total)) } else { 0 }
            $mb    = [int](($proc.WorkingSet64) / 1MB)
            Show-ProgressBar -Label "  Scanning ($mb MB)" -Percent $pct -BarWidth 40
            Start-Sleep -Milliseconds 80
        }
        Show-ProgressBar -Label "  Scanning" -Percent 100 -BarWidth 40
        Write-Host ""

        $hits = @($ps2.EndInvoke($handle2))
        $ps2.Dispose(); $rs2.Close(); $rs2.Dispose()
        $scanSw.Stop()
        $scannedPids += [string]$proc.Id

        if ($hits -and $hits.Length -gt 0) {
            foreach ($h in $hits) { $allMatchedSigs.Add($h) | Out-Null }
            Write-Host "  [!] PID $($proc.Id) — $($scanSw.ElapsedMilliseconds) ms — $($hits.Length) hit(s)" -ForegroundColor Red
        } else {
            Write-Host "  [+] PID $($proc.Id) — $($scanSw.ElapsedMilliseconds) ms — clean" -ForegroundColor DarkGreen
        }
        Write-Host ""
    }

    $detected = $allMatchedSigs.Count -gt 0

    if ($mcUsername -eq "Unknown") {
        $accountsPath = "$env:APPDATA\.minecraft\launcher_accounts.json"
        if (Test-Path $accountsPath) {
            try {
                $json     = Get-Content $accountsPath -Raw | ConvertFrom-Json
                $activeId = $json.activeAccountLocalId
                if ($activeId) { $name = $json.accounts.$activeId.minecraftProfile.name; if ($name) { $mcUsername = $name } }
                if ($mcUsername -eq "Unknown") {
                    foreach ($prop in $json.accounts.PSObject.Properties) {
                        $name = $prop.Value.minecraftProfile.name; if ($name) { $mcUsername = $name; break }
                    }
                }
            } catch { }
        }
    }
    if ($mcUsername -eq "Unknown") { $mcUsername = $env:USERNAME }

    Write-Host ("-" * 65) -ForegroundColor DarkGray
    Write-Host ""

    if ($detected) {
        Write-Host "  Lagoon Fucked" -ForegroundColor Red
    } else {
        Write-Host "  proccess clean" -ForegroundColor Green
    }

    Send-DiscordWebhook -WebhookUrl $WEBHOOK_URL -MinecraftUsername $mcUsername `
        -Detected $detected -SigCount $allMatchedSigs.Count -ScannedPids $scannedPids

    Write-Host ""
    Write-Host ("-" * 65) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press Enter to exit..." -ForegroundColor DarkGray
    Read-Host | Out-Null

} finally {
    Remove-SigFile
}

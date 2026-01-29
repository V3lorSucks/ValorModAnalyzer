# Valor Combined Mod Analyzer - PowerShell Script
# Developed by: DrValor
# Based on work by: Hadron, TonyNoh, YarpLetapStan
# Scans Minecraft mods for suspicious patterns and verifies against known databases

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Valor Mod Analyzer v2.0" -ForegroundColor Cyan
Write-Host "Security Assessment Tool" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Developed by: DrValor" -ForegroundColor Gray
Write-Host "Based on work by: Hadron, TonyNoh, YarpLetapStan" -ForegroundColor DarkGray
Write-Host ""

# Get mods folder path
Write-Host "Enter path to the mods folder: " -NoNewline
Write-Host "(press Enter to use default)" -ForegroundColor DarkGray
$mods = Read-Host "PATH"
Write-Host

if (-not $mods) {
    $mods = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    Write-Host "Continuing with $mods`n" -ForegroundColor White
}

if (-not (Test-Path $mods -PathType Container)) {
    Write-Host "[ERROR] Invalid Path!" -ForegroundColor Red
    Write-Host "The directory does not exist or is not accessible." -ForegroundColor Yellow
    Write-Host
    Write-Host "Tried to access: $mods" -ForegroundColor Gray
    Write-Host
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "   [SYSTEM] Initiating security scan: $mods" -ForegroundColor Green
Write-Host

# Check Minecraft uptime
$process = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $process) { $process = Get-Process java -ErrorAction SilentlyContinue }

if ($process) {
    try {
        $elapsedTime = (Get-Date) - $process.StartTime
        Write-Host "[PROCESS INFO] Minecraft Uptime" -ForegroundColor DarkCyan
        Write-Host "   $($process.Name) PID $($process.Id) started at $($process.StartTime)" -ForegroundColor Gray
        Write-Host "   Running for: $($elapsedTime.Hours)h $($elapsedTime.Minutes)m $($elapsedTime.Seconds)s" -ForegroundColor Gray
        Write-Host ""
    } catch {}
}

# ==================== Fabric AddMods Detector ====================
Write-Host "   [SYSTEM SCAN] Fabric External Mods Verification" -ForegroundColor Yellow
Write-Host "   --------------------------------------------------------" -ForegroundColor DarkYellow
Write-Host ""

# Find all javaw.exe processes
$javaProcesses = Get-Process -Name javaw -ErrorAction SilentlyContinue

if ($javaProcesses.Count -eq 0) {
    Write-Host "No javaw.exe processes found." -ForegroundColor Yellow
    Write-Host "Make sure Minecraft is running." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "Scanning $($javaProcesses.Count) Java process(es)..." -ForegroundColor White
    Write-Host ""

    $foundFabricAddMods = $false

    foreach ($proc in $javaProcesses) {
        # Get full command line
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
        
        if ($commandLine -match '-Dfabric\.addMods') {
            $foundFabricAddMods = $true
                    
            Write-Host "   [WARNING] External Fabric mod loading detected" -ForegroundColor Yellow
            Write-Host "   Process ID: $($proc.Id)" -ForegroundColor Yellow
            Write-Host "   Status: External mod loading active" -ForegroundColor Yellow
            Write-Host ""
                    
            # Extract the fabric.addMods argument
            if ($commandLine -match '-Dfabric\.addMods=([\^\s]+)') {
                $fabricAddModsValue = $matches[1]
                Write-Host "-Dfabric.addMods=$fabricAddModsValue" -ForegroundColor Magenta
            }
                    
            Write-Host ""
            Write-Host "   [INFO] Additional mods loaded outside standard directory" -ForegroundColor Yellow
            Write-Host ""
        }
    }

    if (-not $foundFabricAddMods) {
        Write-Host "   [STATUS] No unauthorized external mod loading detected" -ForegroundColor Green
        Write-Host ""
    }
}

function Get-SHA1($filePath) { return (Get-FileHash -Path $filePath -Algorithm SHA1).Hash }

function Get-ZoneIdentifier($filePath) {
    try {
        if ($ads = Get-Content -Raw -Stream Zone.Identifier $filePath -ErrorAction SilentlyContinue | Where-Object { $_ -match "HostUrl=(.+)" }) {
            $url = $matches[1]
            return @{
                Source = switch -regex ($url) {
                    "modrinth\.com" { "Modrinth"; break }
                    "curseforge\.com" { "CurseForge"; break }
                    "github\.com" { "GitHub"; break }
                    "discord" { "Discord"; break }
                    "mediafire\.com" { "MediaFire"; break }
                    "dropbox\.com" { "Dropbox"; break }
                    "drive\.google\.com" { "Google Drive"; break }
                    "mega\.nz|mega\.co\.nz" { "MEGA"; break }
                    "anydesk\.com" { "AnyDesk"; break }
                    "doomsdayclient\.com" { "DoomsdayClient"; break }
                    "prestigeclient\.vip" { "PrestigeClient"; break }
                    "198macros\.com" { "198Macros"; break }
                    default { 
                        if ($url -match "https?://(?:www\.)?([^/]+)") {
                            $matches[1]
                        } else {
                            "Other"
                        }
                    }
                }
                URL = $url
                IsModrinth = $url -match "modrinth\.com"
            }
        }
    } catch {}
    return @{ Source = "Unknown"; URL = ""; IsModrinth = $false }
}

function Get-Mod-Info-From-Jar($jarPath) {
    $modInfo = @{ ModId = ""; Name = ""; Version = ""; Description = ""; Authors = @(); License = ""; Contact = @{}; Icon = ""; Environment = ""; Entrypoints = @{}; Mixins = @(); AccessWidener = ""; Depends = @{}; Suggests = @{}; Breaks = @{}; Conflicts = @{}; ModLoader = "" }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
        
        # Check for fabric.mod.json
        if ($entry = $zip.Entries | Where-Object { $_.Name -eq 'fabric.mod.json' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $fabricData = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $modInfo.ModId = $fabricData.id; $modInfo.Name = $fabricData.name; $modInfo.Version = $fabricData.version
            $modInfo.Description = $fabricData.description; $modInfo.Authors = if ($fabricData.authors -is [array]) { $fabricData.authors } else { @($fabricData.authors) }
            $modInfo.License = $fabricData.license; $modInfo.Contact = $fabricData.contact; $modInfo.Icon = $fabricData.icon
            $modInfo.Environment = $fabricData.environment; $modInfo.Entrypoints = $fabricData.entrypoints
            $modInfo.Mixins = if ($fabricData.mixins -is [array]) { $fabricData.mixins } else { @($fabricData.mixins) }
            $modInfo.AccessWidener = $fabricData.accessWidener; $modInfo.Depends = $fabricData.depends; $modInfo.Suggests = $fabricData.suggests
            $modInfo.Breaks = $fabricData.breaks; $modInfo.Conflicts = $fabricData.conflicts; $modInfo.ModLoader = "Fabric"
            
            $zip.Dispose()
            return $modInfo
        }
        
        # Check for mods.toml (Forge/NeoForge)
        if ($entry = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/mods.toml' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $tomlContent = $reader.ReadToEnd()
            $reader.Close()
            
            if ($tomlContent -match 'modId\s*=\s*"([^"]+)"') { $modInfo.ModId = $matches[1] }
            if ($tomlContent -match 'displayName\s*=\s*"([^"]+)"') { $modInfo.Name = $matches[1] }
            if ($tomlContent -match 'version\s*=\s*"([^"]+)"') { $modInfo.Version = $matches[1] }
            if ($tomlContent -match 'description\s*=\s*"([^"]+)"') { $modInfo.Description = $matches[1] }
            if ($tomlContent -match 'authors\s*=\s*"([^"]+)"') { $modInfo.Authors = @($matches[1]) }
            
            $modInfo.ModLoader = "Forge/NeoForge"
            $zip.Dispose()
            return $modInfo
        }
        
        # Check for mixin configs
        if ($entry = $zip.Entries | Where-Object { $_.Name -match '\.mixins\.json$' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $mixinData = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
            $reader.Close()
            if ($mixinData.package -and -not $modInfo.ModId) {
                $packageParts = $mixinData.package -split '\.'
                if ($packageParts.Count -ge 2) { $modInfo.ModId = $packageParts[-2] }
            }
        }
        
        # Check for manifest
        if ($entry = $zip.Entries | Where-Object { $_.Name -eq 'MANIFEST.MF' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $manifestContent = $reader.ReadToEnd()
            $reader.Close()
            
            $lines = $manifestContent -split "`n"
            foreach ($line in $lines) {
                if ($line -match 'Implementation-Title:\s*(.+)' -and -not $modInfo.Name) { $modInfo.Name = $matches[1].Trim() }
                if ($line -match 'Implementation-Version:\s*(.+)' -and -not $modInfo.Version) { $modInfo.Version = $matches[1].Trim() }
                if ($line -match 'Specification-Title:\s*(.+)' -and -not $modInfo.Name) { $modInfo.Name = $matches[1].Trim() }
            }
        }
        
        $zip.Dispose()
    } catch {}
    return $modInfo
}

function Fetch-Modrinth-By-Hash($hash) {
    try {
        $response = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$hash" -Method Get -UseBasicParsing
        if ($response.project_id) {
            $projectData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($response.project_id)" -Method Get -UseBasicParsing
            $fileInfo = $response.files[0]
            
            return @{ 
                Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $fileInfo.size
                VersionNumber = $response.version_number; FileName = $fileInfo.filename
                ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($response.id)"
                FoundByHash = $true; ExactMatch = $true; IsLatestVersion = $false; MatchType = "Exact Hash"
                LoaderType = if ($response.loaders -contains "fabric") { "Fabric" } elseif ($response.loaders -contains "forge") { "Forge" } else { "Unknown" }
            }
        }
    } catch {}
    return @{ Name = ""; Slug = ""; ExpectedSize = 0; VersionNumber = ""; FileName = ""; FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $false; LoaderType = "Unknown" }
}

function Fetch-Modrinth-By-ModId($modId, $version, $preferredLoader = "Fabric") {
    try {
        $projectData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$modId" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($projectData.id) {
            $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$modId/version" -Method Get -UseBasicParsing
            
            foreach ($ver in $versionsData) {
                $matchesLoader = ($ver.loaders -contains $preferredLoader.ToLower())
                
                if ($matchesLoader) {
                    $file = $ver.files[0]
                    $loader = if ($ver.loaders -contains "fabric") { "Fabric" } elseif ($ver.loaders -contains "forge") { "Forge" } else { $ver.loaders[0] }
                    
                    return @{
                        Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $file.size
                        VersionNumber = $ver.version_number; FileName = $file.filename
                        ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($ver.id)"
                        FoundByHash = $false; ExactMatch = $false; IsLatestVersion = ($versionsData[0].id -eq $ver.id)
                        MatchType = "Latest Version ($loader)"; LoaderType = $loader
                    }
                }
            }
            
            if ($versionsData.Count -gt 0) {
                $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                
                return @{
                    Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $latestFile.size
                    VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                    ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($latestVersion.id)"
                    FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                    MatchType = "Latest Version ($loader)"; LoaderType = $loader
                }
            }
        }
    } catch {
        try {
            $searchData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/search?query=`"$modId`"&facets=`"[[`"project_type:mod`"]]`"&limit=5" -Method Get -UseBasicParsing
            
            if ($searchData.hits -and $searchData.hits.Count -gt 0) {
                $bestMatch = $null; $bestScore = 0
                foreach ($hit in $searchData.hits) {
                    $score = 0
                    if ($hit.slug -eq $modId) { $score += 100 }
                    if ($hit.project_id -eq $modId) { $score += 100 }
                    if ($hit.title -eq $modId) { $score += 80 }
                    if ($hit.title -match $modId) { $score += 50 }
                    if ($hit.slug -match $modId) { $score += 40 }
                    
                    if ($score -gt $bestScore) { $bestScore = $score; $bestMatch = $hit }
                }
                
                if ($bestMatch) {
                    $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($bestMatch.project_id)/version" -Method Get -UseBasicParsing
                    
                    if ($versionsData.Count -gt 0) {
                        $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                        $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                        
                        return @{
                            Name = $bestMatch.title; Slug = $bestMatch.slug; ExpectedSize = $latestFile.size
                            VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                            ModrinthUrl = "https://modrinth.com/mod/$($bestMatch.slug)/version/$($latestVersion.id)"
                            FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                            MatchType = "Latest Version ($loader)"; LoaderType = $loader
                        }
                    }
                }
            }
        } catch {}
    }
    
    return @{ Name = ""; Slug = ""; ExpectedSize = 0; VersionNumber = ""; FileName = ""; FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $false; MatchType = "No Match"; LoaderType = "Unknown" }
}

function Fetch-Modrinth-By-Filename($filename, $preferredLoader = "Fabric") {
    $cleanFilename = $filename -replace '\.temp\.jar$|\.tmp\.jar$|_1\.jar$', '.jar'
    $modNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($cleanFilename)
    
    if ($filename -match '(?i)fabric') { $preferredLoader = "Fabric" }
    elseif ($filename -match '(?i)forge') { $preferredLoader = "Forge" }
    
    $localVersion = ""; $baseName = $modNameWithoutExt
    if ($modNameWithoutExt -match '[-_](v?[\d\.]+(?:-[a-zA-Z0-9]+)?)$') {
        $localVersion = $matches[1]; $baseName = $modNameWithoutExt -replace '[-_](v?[\d\.]+(?:-[a-zA-Z0-9]+)?)$', ''
    }
    
    $baseName = $baseName -replace '(?i)-fabric$|-forge$', ''
    
    foreach ($slug in @($baseName.ToLower(), $modNameWithoutExt.ToLower())) {
        try {
            $projectData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$slug" -Method Get -UseBasicParsing
            $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$slug/version" -Method Get -UseBasicParsing
            
            foreach ($version in $versionsData) {
                foreach ($file in $version.files) {
                    if ($file.filename -eq $cleanFilename -or $file.filename -eq $filename) {
                        $loader = if ($version.loaders -contains "fabric") { "Fabric" } elseif ($version.loaders -contains "forge") { "Forge" } else { $version.loaders[0] }
                        
                        return @{
                            Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $file.size
                            VersionNumber = $version.version_number; FileName = $file.filename
                            ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($version.id)"
                            FoundByHash = $false; ExactMatch = $true; IsLatestVersion = ($versionsData[0].id -eq $version.id)
                            MatchType = "Exact Filename"; LoaderType = $loader
                        }
                    }
                }
            }
            
            foreach ($version in $versionsData) {
                $matchesLoader = ($version.loaders -contains $preferredLoader.ToLower())
                
                if ($matchesLoader) {
                    $file = $version.files[0]
                    $loader = if ($version.loaders -contains "fabric") { "Fabric" } elseif ($version.loaders -contains "forge") { "Forge" } else { $version.loaders[0] }
                    
                    return @{
                        Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $file.size
                        VersionNumber = $version.version_number; FileName = $file.filename
                        ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($version.id)"
                        FoundByHash = $false; ExactMatch = $false; IsLatestVersion = ($versionsData[0].id -eq $version.id)
                        MatchType = "Latest Version ($loader)"; LoaderType = $loader
                    }
                }
            }
            
            if ($versionsData.Count -gt 0) {
                $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                
                return @{
                    Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $latestFile.size
                    VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                    ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($latestVersion.id)"
                    FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                    MatchType = "Latest Version ($loader)"; LoaderType = $loader
                }
            }
        } catch { continue }
    }
    
    try {
        $searchData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/search?query=`"$baseName`"&facets=`"[[`"project_type:mod`"]]`"&limit=5" -Method Get -UseBasicParsing
        
        if ($searchData.hits -and $searchData.hits.Count -gt 0) {
            $hit = $searchData.hits[0]
            $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($hit.project_id)/version" -Method Get -UseBasicParsing
            
            foreach ($version in $versionsData) {
                foreach ($file in $version.files) {
                    if ($file.filename -eq $cleanFilename -or $file.filename -eq $filename) {
                        $loader = if ($version.loaders -contains "fabric") { "Fabric" } elseif ($version.loaders -contains "forge") { "Forge" } else { $version.loaders[0] }
                        
                        return @{
                            Name = $hit.title; Slug = $hit.slug; ExpectedSize = $file.size
                            VersionNumber = $version.version_number; FileName = $file.filename
                            ModrinthUrl = "https://modrinth.com/mod/$($hit.slug)/version/$($version.id)"
                            FoundByHash = $false; ExactMatch = $true; IsLatestVersion = ($versionsData[0].id -eq $version.id)
                            MatchType = "Exact Filename"; LoaderType = $loader
                        }
                    }
                }
            }
            
            if ($versionsData.Count -gt 0) {
                $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                
                return @{
                    Name = $hit.title; Slug = $hit.slug; ExpectedSize = $latestFile.size
                    VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                    ModrinthUrl = "https://modrinth.com/mod/$($hit.slug)/version/$($latestVersion.id)"
                    FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                    MatchType = "Latest Version ($loader)"; LoaderType = $loader
                }
            }
        }
    } catch {}
    
    return @{ Name = ""; Slug = ""; ExpectedSize = 0; VersionNumber = ""; FileName = ""; FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $false; MatchType = "No Match"; LoaderType = "Unknown" }
}

function Fetch-Megabase($hash) {
    try {
        $response = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$hash" -Method Get -UseBasicParsing
        if (-not $response.error) { return $response.data }
    } catch {}
    return $null
}

# Extensive cheat/hack pattern database - compiled from known malicious mods
$suspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "Hitboxes", "JumpReset", "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "Velocity", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer", 
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod", "Reach",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag",
    "Friends", "NoDelay", "BlockESP", "Krypton", "krypton", "dev.krypton", "Virgin", "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill", "NoJumpDelay", "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "Freecam", "PackSpoof", "Antiknockback", "scrim", "catlean", "Argon",
    "Discord", "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "Grim", "grim",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui", "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Flight", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion",
    "KeyboardMixin", "ClientPlayerInteractionManagerMixin",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "じ.class", "ふ.class", "ぶ.class", "ぷ.class", "た.class",
    "ね.class", "そ.class", "な.class", "ど.class", "ぐ.class",
    "ず.class", "で.class", "つ.class", "べ.class", "せ.class",
    "と.class", "み.class", "び.class", "す.class", "の.class",
    # Additional patterns from 1st analyzer
    "autocrystal", "auto crystal", "cw crystal", "autohitcrystal",
    "autoanchor", "auto anchor", "anchortweaks", "anchor macro",
    "autototem", "auto totem", "legittotem", "inventorytotem", "hover totem",
    "autopot", "auto pot", "velocity",
    "autodoublehand", "auto double hand",
    "autoarmor", "auto armor",
    "automace",
    "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "shieldbreaker", "shield breaker",
    "axespam", "axe spam",
    "pingspoof", "ping spoof",
    "webmacro", "web macro",
    "selfdestruct", "self destruct",
    "hitboxes", "lvstrng",
    "swapBackToOriginalSlot",
    "attackRegisteredThisClick",
    "findKnockbackSword"
)

function Check-Strings($filePath) {
    $stringsFound = [System.Collections.Generic.HashSet[string]]::new()
    
    try {
        $possiblePaths = @(
            "C:\Program Files\Git\usr\bin\strings.exe",
            "C:\Program Files\Git\mingw64\bin\strings.exe",
            "$env:ProgramFiles\Git\usr\bin\strings.exe",
            "C:\msys64\usr\bin\strings.exe",
            "C:\cygwin64\bin\strings.exe"
        )
        
        if ($stringsPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1) {
            $tempFile = Join-Path $env:TEMP "temp_strings_$(Get-Random).txt"
            & $stringsPath $filePath 2>$null | Out-File $tempFile
            if (Test-Path $tempFile) {
                $extractedContent = Get-Content $tempFile -Raw
                Remove-Item $tempFile -Force
                
                foreach ($string in $suspiciousPatterns) {
                    if ($extractedContent -match $string) { $stringsFound.Add($string) | Out-Null }
                }
            }
        } else {
            $content = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($filePath)).ToLower()
            foreach ($string in $suspiciousPatterns) {
                if ($string -eq "velocity") {
                    if ($content -match "velocity(hack|module|cheat|bypass|packet|horizontal|vertical|amount|factor|setting)") {
                        $stringsFound.Add($string) | Out-Null
                    }
                } elseif ($content -match $string) {
                    $stringsFound.Add($string) | Out-Null
                }
            }
        }
    } catch {}
    return $stringsFound
}

# Collections for results
$verifiedMods = @(); $unknownMods = @(); $suspiciousMods = @(); $sizeMismatchMods = @(); $tamperedMods = @(); $allModsInfo = @()

# Process all mods
$jarFiles = Get-ChildItem -Path $mods -Filter *.jar
$totalMods = $jarFiles.Count

if ($jarFiles.Count -eq 0) {
    Write-Host "   [ERROR] No executable modules found in: $mods" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-Host "   [SYSTEM] Discovered $($jarFiles.Count) executable module(s) for analysis" -ForegroundColor Green
Write-Host

# Process all mods
for ($i = 0; $i -lt $jarFiles.Count; $i++) {
    $file = $jarFiles[$i]
    Write-Host "`r   [ANALYZING] Module Scan: $($i+1) / $totalMods - $($file.Name)" -ForegroundColor Yellow -NoNewline
    
    # Get file info
    $hash = Get-SHA1 -filePath $file.FullName
    $actualSize = $file.Length; $actualSizeKB = [math]::Round($actualSize/1KB, 2)
    $zoneInfo = Get-ZoneIdentifier $file.FullName
    $jarModInfo = Get-Mod-Info-From-Jar -jarPath $file.FullName
    
    # Determine preferred loader
    $preferredLoader = "Fabric"
    if ($file.Name -match '(?i)fabric') { $preferredLoader = "Fabric" }
    elseif ($file.Name -match '(?i)forge') { $preferredLoader = "Forge" }
    elseif ($jarModInfo.ModLoader -eq "Fabric") { $preferredLoader = "Fabric" }
    elseif ($jarModInfo.ModLoader -eq "Forge/NeoForge") { $preferredLoader = "Forge" }
    
    # Try to find mod info
    $modData = Fetch-Modrinth-By-Hash -hash $hash
    if (-not $modData.Name -and $jarModInfo.ModId) {
        $modData = Fetch-Modrinth-By-ModId -modId $jarModInfo.ModId -version $jarModInfo.Version -preferredLoader $preferredLoader
    }
    if (-not $modData.Name) {
        $modData = Fetch-Modrinth-By-Filename -filename $file.Name -preferredLoader $preferredLoader
    }
    
    if ($modData.Name) {
        $sizeDiff = $actualSize - $modData.ExpectedSize
        $expectedSizeKB = if ($modData.ExpectedSize -gt 0) { [math]::Round($modData.ExpectedSize/1KB, 2) } else { 0 }
        
        $modEntry = [PSCustomObject]@{ 
            ModName = $modData.Name; FileName = $file.Name; Version = $modData.VersionNumber
            ExpectedSize = $modData.ExpectedSize; ExpectedSizeKB = $expectedSizeKB; ActualSize = $actualSize; ActualSizeKB = $actualSizeKB
            SizeDiff = $sizeDiff; SizeDiffKB = [math]::Round($sizeDiff/1KB, 2); DownloadSource = $zoneInfo.Source; SourceURL = $zoneInfo.URL
            IsModrinthDownload = $zoneInfo.IsModrinth; ModrinthUrl = $modData.ModrinthUrl; IsVerified = $true; MatchType = $modData.MatchType
            ExactMatch = $modData.ExactMatch; IsLatestVersion = $modData.IsLatestVersion; LoaderType = $modData.LoaderType
            PreferredLoader = $preferredLoader; FilePath = $file.FullName; JarModId = $jarModInfo.ModId; JarName = $jarModInfo.Name
            JarVersion = $jarModInfo.Version; JarModLoader = $jarModInfo.ModLoader
        }
        
        $verifiedMods += $modEntry; $allModsInfo += $modEntry
        
        if ($modData.ExpectedSize -gt 0 -and $actualSize -ne $modData.ExpectedSize) {
            $sizeMismatchMods += $modEntry
            if ([math]::Abs($sizeDiff) -gt 1024) { $tamperedMods += $modEntry }
        }
    } elseif ($megabaseData = Fetch-Megabase -hash $hash) {
        $modEntry = [PSCustomObject]@{ 
            ModName = $megabaseData.name; FileName = $file.Name; Version = "Unknown"; ExpectedSize = 0; ExpectedSizeKB = 0
            ActualSize = $actualSize; ActualSizeKB = $actualSizeKB; SizeDiff = 0; SizeDiffKB = 0; DownloadSource = $zoneInfo.Source
            SourceURL = $zoneInfo.URL; IsModrinthDownload = $zoneInfo.IsModrinth; IsVerified = $true; MatchType = "Megabase"
            ExactMatch = $false; IsLatestVersion = $false; LoaderType = "Unknown"; PreferredLoader = $preferredLoader
            FilePath = $file.FullName; JarModId = $jarModInfo.ModId; JarName = $jarModInfo.Name; JarVersion = $jarModInfo.Version
            JarModLoader = $jarModInfo.ModLoader
        }
        
        $verifiedMods += $modEntry; $allModsInfo += $modEntry
    } else {
        $unknownModEntry = [PSCustomObject]@{ 
            FileName = $file.Name; FilePath = $file.FullName; ZoneId = $zoneInfo.URL; DownloadSource = $zoneInfo.Source
            IsModrinthDownload = $zoneInfo.IsModrinth; FileSize = $actualSize; FileSizeKB = $actualSizeKB; Hash = $hash
            ExpectedSize = 0; ExpectedSizeKB = 0; SizeDiff = 0; SizeDiffKB = 0; ModrinthUrl = ""; ModName = ""; MatchType = ""
            ExactMatch = $false; IsLatestVersion = $false; LoaderType = "Unknown"; PreferredLoader = $preferredLoader
            JarModId = $jarModInfo.ModId; JarName = $jarModInfo.Name; JarVersion = $jarModInfo.Version; JarModLoader = $jarModInfo.ModLoader
        }
        
        $unknownMods += $unknownModEntry; $allModsInfo += $unknownModEntry
    }
}

Write-Host "`r$( * 120)`r" -NoNewline

# Try to identify unknown mods
for ($i = 0; $i -lt $unknownMods.Count; $i++) {
    $mod = $unknownMods[$i]
    $modrinthInfo = if ($mod.JarModId) { Fetch-Modrinth-By-ModId -modId $mod.JarModId -version $mod.JarVersion -preferredLoader $mod.PreferredLoader }
    if (-not $modrinthInfo -or -not $modrinthInfo.Name) { $modrinthInfo = Fetch-Modrinth-By-Filename -filename $mod.FileName -preferredLoader $mod.PreferredLoader }
    
    if ($modrinthInfo -and $modrinthInfo.Name) {
        $mod.ModName = $modrinthInfo.Name; $mod.ExpectedSize = $modrinthInfo.ExpectedSize
        $mod.ExpectedSizeKB = if ($modrinthInfo.ExpectedSize -gt 0) { [math]::Round($modrinthInfo.ExpectedSize/1KB, 2) } else { 0 }
        $mod.SizeDiff = $mod.FileSize - $modrinthInfo.ExpectedSize
        $mod.SizeDiffKB = [math]::Round(($mod.FileSize - $modrinthInfo.ExpectedSize)/1KB, 2)
        $mod.ModrinthUrl = $modrinthInfo.ModrinthUrl; $mod.ModName = $modrinthInfo.Name; $mod.MatchType = $modrinthInfo.MatchType
        $mod.ExactMatch = $modrinthInfo.ExactMatch; $mod.IsLatestVersion = $modrinthInfo.IsLatestVersion; $mod.LoaderType = $modrinthInfo.LoaderType
        
        for ($j = 0; $j -lt $allModsInfo.Count; $j++) {
            if ($allModsInfo[$j].FileName -eq $mod.FileName) {
                $allModsInfo[$j].ModName = $modrinthInfo.Name; $allModsInfo[$j].ExpectedSize = $modrinthInfo.ExpectedSize
                $allModsInfo[$j].ExpectedSizeKB = $mod.ExpectedSizeKB; $allModsInfo[$j].SizeDiff = $mod.SizeDiff
                $allModsInfo[$j].SizeDiffKB = $mod.SizeDiffKB; $allModsInfo[$j].ModrinthUrl = $modrinthInfo.ModrinthUrl
                $allModsInfo[$j].ModName = $modrinthInfo.Name; $allModsInfo[$j].MatchType = $modrinthInfo.MatchType
                $allModsInfo[$j].ExactMatch = $modrinthInfo.ExactMatch; $allModsInfo[$j].IsLatestVersion = $modrinthInfo.IsLatestVersion
                $allModsInfo[$j].LoaderType = $modrinthInfo.LoaderType
                break
            }
        }
    }
}

# Deep pattern scan on unknown mods
if ($unknownMods.Count -gt 0) {
    Write-Host "   [DEEP_ANALYSIS] Examining $($unknownMods.Count) unverified module(s) for threat signatures..." -ForegroundColor Cyan
    
    $idx = 0
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $pattern = '(' + ($suspiciousPatterns -join '|') + ')'
        $regex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Compiled)
        
        foreach ($mod in $unknownMods) {
            $idx++
            Write-Host "`r   [DEEP_SCAN] Pattern Recognition: $idx/$($unknownMods.Count) - $($mod.FileName)" -ForegroundColor Yellow -NoNewline
            
            $detected = [System.Collections.Generic.HashSet[string]]::new()
            
            try {
                $archive = [System.IO.Compression.ZipFile]::OpenRead($mod.FilePath)
                
                foreach ($entry in $archive.Entries) {
                    $matches = $regex.Matches($entry.FullName)
                    foreach ($m in $matches) {
                        [void]$detected.Add($m.Value)
                    }
                    
                    if ($entry.FullName -match '\.(class|json)$' -or $entry.FullName -match 'MANIFEST\.MF') {
                        try {
                            $stream = $entry.Open()
                            $reader = New-Object System.IO.StreamReader($stream)
                            $content = $reader.ReadToEnd()
                            $reader.Close()
                            $stream.Close()
                            
                            $contentMatches = $regex.Matches($content)
                            foreach ($m in $contentMatches) {
                                [void]$detected.Add($m.Value)
                            }
                        } catch {
                            # Entry read failed, skip
                        }
                    }
                }
                
                $archive.Dispose()
                
                if ($detected.Count -gt 0) {
                    $suspiciousMods += [PSCustomObject]@{ 
                        FileName = $mod.FileName
                        DetectedPatterns = $detected
                    }
                }
                
            } catch {
                # Archive corrupted or inaccessible
                continue
            }
        }
    } catch {
        Write-Host "`r   [ERROR] During deep analysis: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`r$( * 120)`r" -NoNewline
}

# Also scan verified mods for suspicious patterns
Write-Host "   [PATTERN_SCAN] Inspecting verified modules for malicious signatures..." -ForegroundColor Cyan
$counter = 0
foreach ($mod in $allModsInfo) {
    $counter++
    Write-Host "`r   [PATTERN_SCAN] Signature Verification: $counter / $($allModsInfo.Count) - $($mod.FileName)" -ForegroundColor Yellow -NoNewline
    
    if ($modStrings = Check-Strings $mod.FilePath) {
        $suspiciousMods += [PSCustomObject]@{ 
            FileName = $mod.FileName; DetectedPatterns = $modStrings;
            ModName = $mod.ModName; DownloadSource = $mod.DownloadSource; 
            IsVerifiedMod = ($mod.IsVerified -eq $true); HasSizeMismatch = ($mod.SizeDiffKB -ne 0 -and [math]::Abs($mod.SizeDiffKB) -gt 1)
        }
    }
}

Write-Host "`r$( * 120)`r" -NoNewline

# Results output
Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
Write-Host "=== Verification Results ===" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan

if ($verifiedMods.Count -gt 0) {
    Write-Host "   VERIFIED MODS ($($verifiedMods.Count))" -ForegroundColor Green
    Write-Host "   " + ("-" * 40) -ForegroundColor DarkGray
    
    foreach ($mod in $verifiedMods) {
        $isSuspicious = $suspiciousMods.FileName -contains $mod.FileName
        $isTampered = $tamperedMods.FileName -contains $mod.FileName
        
        if ($isTampered) { Write-Host "     [INTEGRITY MISMATCH] " -ForegroundColor Red -NoNewline }
        elseif ($isSuspicious) { Write-Host "     [SIGNATURE MATCH] " -ForegroundColor Yellow -NoNewline }
        else { Write-Host "     [VERIFIED] " -ForegroundColor Green -NoNewline }
        
        Write-Host "$($mod.ModName)" -ForegroundColor White -NoNewline
        Write-Host " | " -ForegroundColor Gray -NoNewline
        Write-Host "$($mod.FileName)" -ForegroundColor DarkGray -NoNewline
        
        if ($mod.Version -and $mod.Version -ne "Unknown") {
            Write-Host " | Version: $($mod.Version)" -ForegroundColor DarkGray -NoNewline
        }
        
        $matchIndicator = switch ($mod.MatchType) {
            { $_ -match "Exact" } { @{ Symbol = "| EXACT MATCH"; Color = "Green" } }
            { $_ -match "Closest" } { @{ Symbol = "| CLOSE MATCH"; Color = "Yellow" } }
            { $_ -match "Latest" } { @{ Symbol = "| LATEST VERSION"; Color = "Cyan" } }
            default { $null }
        }
        
        if ($matchIndicator) { Write-Host $matchIndicator.Symbol -ForegroundColor $matchIndicator.Color -NoNewline }
        if ($mod.LoaderType -ne "Unknown") { Write-Host " | Loader: $($mod.LoaderType)" -ForegroundColor $(if ($mod.LoaderType -eq "Fabric") { 'Magenta' } else { 'Yellow' }) -NoNewline }
        if ($mod.DownloadSource -ne "Unknown") { Write-Host " | Source: $($mod.DownloadSource)" -ForegroundColor $(if ($mod.IsModrinthDownload) { 'Green' } else { 'DarkYellow' }) }
        else { Write-Host "" }
        
        if ($mod.ExpectedSize -gt 0) {
            if ($mod.ActualSize -eq $mod.ExpectedSize) {
                Write-Host "        Integrity: VERIFIED | Size: $($mod.ActualSizeKB) KB" -ForegroundColor Green
            } else {
                $sign = if ($mod.SizeDiffKB -gt 0) { "+" } else { "" }
                $color = if ($isTampered) { 'Magenta' } else { 'Yellow' }
                Write-Host "        Integrity: MODIFIED | Size: $($mod.ActualSizeKB) KB (Expected: $($mod.ExpectedSizeKB) KB, Change: $sign$($mod.SizeDiffKB) KB)" -ForegroundColor $color
            }
        }
    }
    Write-Host ""
}

if ($unknownMods.Count -gt 0) {
    Write-Host "   [VERIFICATION RESULTS] UNKNOWN MODS ($($unknownMods.Count))" -ForegroundColor Yellow
    Write-Host "   " + ("-" * 40) -ForegroundColor DarkGray
    foreach ($mod in $unknownMods) {
        $name = $mod.FileName
        if ($name.Length -gt 50) {
            $name = $name.Substring(0, 47) + "..."
        }
        
        Write-Host "     [VERIFICATION SOURCE UNAVAILABLE] $name" -ForegroundColor Yellow
        $sourceText = if ($mod.DownloadSource) { "        Source Origin: $($mod.DownloadSource)" } else { "        Source Origin: Unknown" }
        Write-Host $sourceText -ForegroundColor DarkYellow
        Write-Host ""
    }
}

if ($suspiciousMods.Count -gt 0) {
    Write-Host "   [SIGNATURE MATCHES] SUSPICIOUS PATTERNS DETECTED ($($suspiciousMods.Count))" -ForegroundColor Red
    Write-Host "   " + ("-" * 40) -ForegroundColor DarkGray
    Write-Host ""
    foreach ($mod in $suspiciousMods) {
        Write-Host "     [SUSPICIOUS PATTERN DETECTED]" -ForegroundColor Red
        Write-Host "       File: $($mod.FileName)" -ForegroundColor Yellow
        
        if ($mod.ModName) {
            Write-Host "       Product: $($mod.ModName)" -ForegroundColor Yellow
        }
        
        Write-Host "       Suspicious Patterns Identified:" -ForegroundColor Red
        
        $patterns = $mod.DetectedPatterns | Sort-Object
        foreach ($p in $patterns) {
            Write-Host "         [-] $p" -ForegroundColor White
        }
        
        Write-Host ""
    }
}

if ($tamperedMods.Count -gt 0) {
    Write-Host "   [INTEGRITY FINDINGS] MODIFIED FILES DETECTED ($($tamperedMods.Count))" -ForegroundColor Magenta
    Write-Host "   " + ("-" * 40) -ForegroundColor DarkGray
    
    foreach ($mod in $tamperedMods) {
        $sign = if ($mod.SizeDiffKB -gt 0) { "+" } else { "" }
        Write-Host "     [MODIFICATION DETECTED] $($mod.FileName)" -ForegroundColor Magenta
        Write-Host "       Product: $($mod.ModName)" -ForegroundColor Yellow
        
        if ($mod.LoaderType -ne "Unknown") {
            $loaderColor = if ($mod.LoaderType -eq "Fabric") { 'Magenta' } else { 'Yellow' }
            Write-Host "       Platform: $($mod.LoaderType)" -ForegroundColor $loaderColor
        }
        
        Write-Host "       Original Size: $($mod.ExpectedSizeKB) KB | Current Size: $($mod.ActualSizeKB) KB | Change: $sign$($mod.SizeDiffKB) KB" -ForegroundColor Magenta
        Write-Host "       File integrity compromised - significant size deviation detected!" -ForegroundColor Red
        
        if ($mod.ModrinthUrl) {
            Write-Host "       Reference Link: $($mod.ModrinthUrl)" -ForegroundColor DarkGray
        }
        
        Write-Host ""
    }
}

Write-Host "   [SCAN SUMMARY] ANALYSIS COMPLETE" -ForegroundColor Cyan
Write-Host "   " + ("=" * 50) -ForegroundColor Blue
Write-Host "       Total files analyzed: " -ForegroundColor Gray -NoNewline
Write-Host "$totalMods" -ForegroundColor White
Write-Host "       Verified modules: " -ForegroundColor Gray -NoNewline
Write-Host "$($verifiedMods.Count)" -ForegroundColor Green
Write-Host "       Unverified files: " -ForegroundColor Gray -NoNewline
Write-Host "$($unknownMods.Count)" -ForegroundColor Yellow
Write-Host "       Signature matches: " -ForegroundColor Gray -NoNewline
Write-Host "$($suspiciousMods.Count)" -ForegroundColor Red
Write-Host "       Integrity mismatches: " -ForegroundColor Gray -NoNewline
Write-Host "$($tamperedMods.Count)" -ForegroundColor Magenta
Write-Host
Write-Host "   " + ("=" * 50) -ForegroundColor Blue
Write-Host ""
Write-Host "   Security scan completed." -ForegroundColor Cyan
Write-Host ""
Write-Host "   Developed by: DrValor" -ForegroundColor Gray
Write-Host "   Based on work by: Hadron, TonyNoh, YarpLetapStan" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   " + ("=" * 50) -ForegroundColor Blue
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

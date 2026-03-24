# Valor Mod Analyzer

**Version:** 3.0 Enhanced  
**Developed by:** DrValor  
**Platform:** PowerShell (Windows)  

## Overview

Valor Mod Analyzer is a comprehensive security scanning tool designed to detect malicious, suspicious, and unauthorized Minecraft mods. It employs multi-layered detection methodologies to identify cheat clients, hacked clients, and potentially dangerous modifications.

---

## Detection Capabilities

### 1. **Pattern-Based Detection**
Scans mod files for known cheat/hack patterns and strings extracted from an extensive database including:

#### Combat Cheats
- **AimAssist / Aim Assist** - Automated aim assistance
- **AutoCrystal / Auto Crystal** - Automated crystal placement and detonation
- **AutoAnchor / Auto Anchor** - Automated anchor usage in Nether
- **AutoTotem / Auto Totem** - Automatic totem switching
- **AutoPot / Auto Pot** - Automatic potion throwing
- **AutoArmor / Auto Armor** - Automatic armor management
- **AutoClicker / Auto Clicker** - Automated clicking
- **TriggerBot / Trigger Bot** - Automated attack triggering
- **KillAura** - 360-degree attack automation
- **Criticals** - Guaranteed critical hits
- **AntiMissClick** - Miss-click prevention

#### Movement & Positioning
- **Velocity / AntiKnockback** - Knockback manipulation
- **Flight / Fly** - Flight capabilities
- **Speed / Step** - Movement speed enhancement
- **NoFall** - Fall damage prevention
- **Timer** - Game speed manipulation
- **JumpReset** - Jump cooldown manipulation
- **SprintReset** - Sprint manipulation
- **FakeLag** - Lag simulation
- **PingSpoof** - Ping manipulation

#### Visual & Information
- **ESP / Wallhack** - Entity highlighting through walls
- **BoxESP** - Bounding box visualization
- **Freecam** - Detached camera view
- **FullBright / NightVision** - Enhanced visibility
- **Xray / CaveFinder** - Ore visualization
- **BlockESP** - Specific block highlighting
- **Health Indicators** - Enemy health display

#### Inventory & Utility
- **InventoryTotem** - Totem management while in inventory
- **HoverTotem / Hover Totem** - Totem preview
- **FakeInv / Fake Inventory** - Fake inventory screen
- **ChestSteal** - Automatic chest looting
- **Refill** - Inventory refill automation
- **FastPlace / NoDelay** - Rapid block placement
- **AutoEat** - Automatic food consumption
- **AutoMine** - Automatic mining
- **ItemExploit** - Item duplication/manipulation
- **invsee** - View other players' inventories

#### Exploits & Bypasses
- **ShieldBreaker / Shield Breaker** - Shield disabling
- **SilentAim** - Server-side aim assistance
- **Reach** - Extended reach distance
- **Hitboxes** - Enlarged hitbox detection
- **Wtap** - Combo maintenance
- **AxeSpam / Axe Spam** - Shield-breaking axe combos
- **WebMacro / Web Macro** - Macro automation
- **SelfDestruct / Self Destruct** - Evidence destruction
- **AuthBypass** - Authentication bypass
- **Antiknockback** - Knockback resistance
- **PackSpoof** - Resource pack spoofing

#### Known Malicious Clients
Detection strings from identified cheat clients:
- Chainlibs (obfuscated class names)
- Dqrkis Client
- Hadron, TonyNoh, YarpLepstan signatures
- Prestige Client components
- Doomsday Client references

---

### 2. **Deep String Extraction**
Utilizes system `strings.exe` utility to extract embedded strings from compiled JAR files when available, enabling detection of:
- Obfuscated cheat strings
- Hidden class references
- Embedded URLs and endpoints
- Encoded payload references

---

### 3. **Bytecode Analysis & Bypass Detection**
Advanced static analysis of Java bytecode to identify:

#### Code Injection Capabilities
- **Runtime.exec()** - Arbitrary OS command execution
- **HTTP File Download** - Remote payload fetching
- **HTTP POST Exfiltration** - Data transmission to external servers

#### Obfuscation Detection
- **Heavy Obfuscation** - ≥25% single-letter path segments (a/b/c style)
- **Numeric Class Names** - Numeric-only class identifiers (e.g., 1234.class)
- **Unicode Class Names** - Non-ASCII character usage in class names
- **Single-Letter Classes** - Excessive single-character class names (>15 instances)

#### Structural Anomalies
- **Suspicious Nested JARs** - Unsigned/unknown dependency wrappers
- **Hollow Shell** - Minimal outer classes wrapping single nested JAR
- **Fake Mod Identity** - Claims legitimate mod ID but contains malicious code

---

### 4. **External Mod Loading Detection**
Detects mods loaded outside the standard mods folder:

#### Fabric AddMods Argument
- Scans running Java processes for `-Dfabric.addMods` JVM arguments
- Parses argfile references containing fabric.addMods directives
- Identifies external mod directories and individual JAR paths
- Validates accessibility of external mod locations

#### JavaAgent Detection
- Identifies suspicious `-javaagent:` arguments
- Filters known legitimate agents (Modrinth Launcher, metadata.jar, NewLaunch.jar)
- Flags arbitrary code injection vectors
- Warns of potential anti-cheat bypass attempts

---

### 5. **File Attribute Manipulation Detection**
Identifies attempts to hide mods using Windows file attributes:

- **Hidden Attribute (+h)** - Files hidden via `attrib +h`
- **System Attribute (+s)** - Files marked as system files
- **Read-Only Attribute (+r)** - Write-protected files
- **Prefetch Manipulation** - Protected Prefetch file modifications

Scans entire mods folder recursively for attribute anomalies on both mod files and auxiliary files.

---

### 6. **Mod Integrity Verification**
Cross-references mods against official databases:

#### Modrinth API Integration
- **Hash-based Verification** - SHA1 hash matching against Modrinth database
- **ModID Lookup** - Version verification via mod identifier
- **Filename Matching** - Fallback filename-based identification
- **Size Validation** - Detects size discrepancies indicating modification

#### Megabase Fallback
- Secondary verification via Megabase API
- Provides additional database coverage

#### Integrity Flags
- **Verified** - Exact hash/signature match with expected size
- **Size Mismatch** - File size differs from official release
- **Tampered** - Significant size difference (>1KB) suggesting modification
- **Modified** - Verified signature but altered file size

---

### 7. **Disallowed Mods Detection**
Maintains database of commonly server-banned mods:

- **Xero's Minimap** - Minimap with entity radar
- **Freecam** - Spectator camera mode
- **Health Indicators** - Boss bar health display
- **ClickCrystals** - One-click crystal activation
- **Mouse Tweaks** - Advanced inventory management
- **Item Scroller** - Bulk item movement
- **Tweakeroo** - Quality-of-life modifications

*Note: These mods may be allowed on some servers but are frequently banned.*

---

### 8. **Nested JAR Scanning**
Recursively analyzes JAR files contained within other JAR files:
- Extracts and scans nested content
- Identifies hidden payloads
- Detects multi-stage loaders
- Analyzes class files and JSON configurations within archives

---

## Detection Output

### Console Reporting
Real-time progress indicators during scanning:
- Percentage-based progress bars
- Spinner animations for intensive operations
- Color-coded severity levels

### HTML Security Report
Generates comprehensive HTML report saved to desktop with:

#### Executive Summary
- Total mods analyzed
- Verified mods count
- Unknown mods count
- Suspicious mods count
- Tampered mods count
- Hidden files count
- Disallowed mods count
- Bypass/Injection detections

#### Detailed Sections
1. **External Mod Directories** - Fabric AddMods detections
2. **Suspicious Java Agents** - Code injection vectors
3. **Minecraft JVM Arguments** - Process-level modifications
4. **Attribute Manipulation** - Hidden file detections
5. **Verified Modules** - Legitimate mod inventory
6. **Unknown Modules** - Unidentified but clean mods
7. **Suspicious Patterns** - Pattern/string matches
8. **Bypass/Injection** - Advanced threat indicators
9. **Tampered Files** - Integrity failures
10. **Disallowed Modules** - Server-banned mods

---

## Technical Specifications

### Supported Mod Loaders
- **Fabric** - Full support
- **Forge/NeoForge** - Full support

### File Analysis Methods
- SHA1 hash computation
- ZIP/JAR archive parsing
- fabric.mod.json extraction
- META-INF/mods.toml parsing
- MANIFEST.MF analysis
- Mixin configuration detection
- Access widener identification

### System Requirements
- Windows 10/11
- PowerShell 5.1 or later
- .NET Framework 4.7+
- Git for Windows (optional, for strings.exe utility)
- Internet connection (for API verification)

---

## Usage

```powershell
.\ValorModAnalyzer.ps1
```

1. Run the script in PowerShell
2. Enter path to mods folder when prompted
3. Default: `%USERPROFILE%\AppData\Roaming\.minecraft\mods`
4. Review console output
5. Examine HTML report on desktop

---

## Limitations

- Requires `strings.exe` from Git for Windows for deep string extraction (falls back to basic pattern matching if unavailable)
- Modrinth API rate limits may affect verification speed
- Some legitimate mods may trigger pattern detections (false positives)
- Heavily obfuscated mods may evade pattern detection
- Offline mode prevents database verification

---

## Security Considerations

Valor Mod Analyzer is a read-only analysis tool:
- Does not modify or delete mod files
- Does not upload files to external services
- Only reads file metadata and content for analysis
- Generates local HTML report
- Requires appropriate permissions to access mods folder and scan running processes

---

## Disclaimer

This tool is provided for educational and security purposes only. The developer assumes no responsibility for:
- False positive or false negative results
- Actions taken based on analysis results
- Compatibility issues with specific mods or launchers
- Changes in mod distribution platforms or APIs

Always verify results manually and review server rules before making decisions about mod usage.

---

## Credits

**Development:** DrValor  
**Inspiration:** Hadron, TonyNoh, YarpLepstan  

**Special Thanks:**
- Modrinth API for mod verification
- Megabase project for additional database coverage
- Minecraft community for pattern contributions

---

## Version History

### v3.0 Enhanced
- Integrated bypass/injection detection
- Added Runtime.exec() and HTTP exfiltration detection
- Enhanced obfuscation analysis
- Improved nested JAR scanning
- Comprehensive HTML reporting
- External mod loading detection
- JavaAgent monitoring
- File attribute manipulation tracking
- Disallowed mods database

---

**Last Updated:** March 24, 2026

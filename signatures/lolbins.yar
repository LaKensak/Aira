/*
    Détection de Living-Off-The-Land Binaries (LOLBins)
    Utilisation d'outils Windows légitimes à des fins malveillantes
*/

rule LOLBin_CertUtil_Download
{
    meta:
        description = "certutil.exe utilisé pour télécharger ou décoder des fichiers"
        severity     = "critical"
    strings:
        $certutil = "certutil" nocase ascii wide
        $decode   = "-decode" nocase ascii wide
        $urlcache = "-urlcache" nocase ascii wide
        $f        = "-f " nocase ascii wide
    condition:
        $certutil and ($decode or $urlcache) and $f
}

rule LOLBin_Regsvr32_Scrobj
{
    meta:
        description = "regsvr32.exe utilisé pour exécuter du code via COM (Squiblydoo)"
        severity     = "critical"
    strings:
        $regsvr = "regsvr32" nocase ascii wide
        $scrobj = "scrobj.dll" nocase ascii wide
        $http   = "http" nocase ascii wide
        $s      = "/s " ascii
        $u      = "/u " ascii
    condition:
        $regsvr and ($scrobj or ($http and ($s or $u)))
}

rule LOLBin_Mshta_JS
{
    meta:
        description = "mshta.exe exécutant du JavaScript/VBScript distant"
        severity     = "critical"
    strings:
        $mshta = "mshta.exe" nocase ascii wide
        $vbs   = "vbscript:" nocase ascii wide
        $js    = "javascript:" nocase ascii wide
        $http  = "http://" nocase ascii wide
        $https = "https://" nocase ascii wide
    condition:
        $mshta and ($vbs or $js or $http or $https)
}

rule LOLBin_Rundll32_Execute
{
    meta:
        description = "rundll32.exe utilisé pour exécuter du code (bypass AppLocker)"
        severity     = "high"
    strings:
        $rundll  = "rundll32" nocase ascii wide
        $js      = "javascript:" nocase ascii wide
        $url     = "url.dll" nocase ascii wide
        $shell32 = "shell32.dll" nocase ascii wide
        $http    = "http" nocase ascii wide
    condition:
        $rundll and ($js or ($url and $http) or $shell32)
}

rule LOLBin_BitsAdmin_Download
{
    meta:
        description = "bitsadmin.exe utilisé pour télécharger des fichiers"
        severity     = "high"
    strings:
        $bits    = "bitsadmin" nocase ascii wide
        $transfer= "/transfer" nocase ascii wide
        $create  = "/create" nocase ascii wide
        $addfile = "/addfile" nocase ascii wide
        $resume  = "/resume" nocase ascii wide
    condition:
        $bits and ($transfer or ($create and $addfile and $resume))
}

rule LOLBin_MSBuild_Execute
{
    meta:
        description = "msbuild.exe utilisé pour exécuter du code C# (bypass whitelist)"
        severity     = "critical"
    strings:
        $msb  = "msbuild" nocase ascii wide
        $task = "UsingTask" ascii wide
        $exec = "Execute" ascii
        $cs   = "Task" ascii
    condition:
        $msb and $task and $exec
}

rule LOLBin_InstallUtil
{
    meta:
        description = "InstallUtil.exe utilisé pour bypass AppLocker"
        severity     = "critical"
    strings:
        $iu      = "InstallUtil" nocase ascii wide
        $install = "[System.ComponentModel.RunInstaller" ascii
        $logfile = "/logfile=" nocase ascii wide
    condition:
        $iu and ($install or $logfile)
}

rule LOLBin_Regasm_Regsvcs
{
    meta:
        description = "regasm.exe/regsvcs.exe utilisé pour exécuter du code .NET"
        severity     = "critical"
    strings:
        $regasm  = "regasm" nocase ascii wide
        $regsvcs = "regsvcs" nocase ascii wide
        $comreg  = "[assembly: ComVisible" ascii
    condition:
        ($regasm or $regsvcs) and $comreg
}

rule LOLBin_WScript_VBS
{
    meta:
        description = "wscript/cscript exécutant du VBScript ou JScript"
        severity     = "high"
    strings:
        $wscript = "wscript.exe" nocase ascii wide
        $cscript = "cscript.exe" nocase ascii wide
        $vbs     = ".vbs" nocase ascii wide
        $js      = ".js" nocase ascii wide
        $http    = "http" nocase ascii wide
    condition:
        ($wscript or $cscript) and ($vbs or $js) and $http
}

rule LOLBin_Powershell_Bypass
{
    meta:
        description = "PowerShell avec multiples flags de bypass de sécurité"
        severity     = "critical"
    strings:
        $ps      = "powershell" nocase ascii wide
        $ep      = "-ExecutionPolicy Bypass" nocase ascii wide
        $ep2     = "-ep bypass" nocase ascii wide
        $ep3     = "Set-ExecutionPolicy Bypass" nocase ascii wide
        $noprof  = "-NoProfile" nocase ascii wide
        $winhide = "-WindowStyle Hidden" nocase ascii wide
        $noint   = "-NonInteractive" nocase ascii wide
        $iex     = "IEX " ascii wide
        $iex2    = "Invoke-Expression" ascii wide
    condition:
        $ps and (
            ($ep or $ep2 or $ep3) or
            ($noprof and $winhide) or
            (($iex or $iex2) and $winhide)
        )
}

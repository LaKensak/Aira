/*
    Détection de patterns C2 (Command & Control)
    Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, DNS tunneling
*/

rule C2_CobaltStrike_DefaultUserAgent
{
    meta:
        description = "User-Agent Cobalt Strike par défaut"
        severity     = "critical"
    strings:
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;ENGB)" ascii
        $ua2 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" ascii
    condition:
        any of them
}

rule C2_CobaltStrike_DefaultEndpoints
{
    meta:
        description = "Endpoints HTTP Cobalt Strike par défaut (malleable C2)"
        severity     = "critical"
    strings:
        $ep1 = "/updates" ascii
        $ep2 = "/pixel.gif" ascii
        $ep3 = "/jquery-3." ascii
        $ep4 = "/submit.php" ascii
        $ep5 = "/s/ref=" ascii
        $ep6 = "/____hhh" ascii
        $ep7 = "/ptj" ascii
        $ep8 = "/dot.gif" ascii
    condition:
        2 of them
}

rule C2_CobaltStrike_Beacon_Strings
{
    meta:
        description = "Strings de beacon Cobalt Strike dans le binaire"
        severity     = "critical"
    strings:
        $cs1 = "beacon" nocase ascii
        $cs2 = "BBHH" ascii
        $cs3 = "pipe\\MSSE-" ascii
        $cs4 = "%s (admin)" ascii
        $cs5 = "Meterpreter" nocase ascii
        $cs6 = "METSRV" ascii
    condition:
        2 of them
}

rule C2_CobaltStrike_ROR13_Shellcode
{
    meta:
        description = "Shellcode Cobalt Strike — boucle ROR13 + hashes API"
        severity     = "critical"
    strings:
        $ror13    = { C1 CF 0D 01 C7 }
        $hash_ll  = { EC 0E 4E 8E }
        $hash_va  = { 91 7C A5 17 }
    condition:
        $ror13 and ($hash_ll or $hash_va)
}

rule C2_Metasploit_Meterpreter
{
    meta:
        description = "Signatures Metasploit Meterpreter"
        severity     = "critical"
    strings:
        $met1 = "meterpreter" nocase ascii
        $met2 = "METSRV" ascii
        $met3 = "ReflectivLoader" ascii
        $met4 = "migrate" ascii
        $met5 = "stdapi" ascii
    condition:
        2 of them
}

rule C2_Sliver_Framework
{
    meta:
        description = "Indicators du C2 framework Sliver"
        severity     = "critical"
    strings:
        $s1 = "sliver" nocase ascii
        $s2 = "Go-http-client" ascii
        $s3 = "github.com/bishopfox/sliver" ascii
        $s4 = "implant" nocase ascii
    condition:
        $s3 or ($s1 and $s2) or ($s1 and $s4)
}

rule C2_HavocFramework
{
    meta:
        description = "Indicators du C2 framework Havoc"
        severity     = "critical"
    strings:
        $h1 = "havoc" nocase ascii
        $h2 = "HavocC2" ascii
        $h3 = "teamserver" nocase ascii
    condition:
        $h1 and ($h2 or $h3)
}

rule C2_BruteRatel
{
    meta:
        description = "Indicators Brute Ratel C4 (BRC4)"
        severity     = "critical"
    strings:
        $b1 = "badger" nocase ascii
        $b2 = "BRC4" ascii
        $b3 = "brute_ratel" nocase ascii
    condition:
        any of them
}

rule C2_DNS_Tunneling
{
    meta:
        description = "Pattern DNS tunneling — APIs DNS + données encodées"
        severity     = "high"
    strings:
        $dns1 = "DnsQueryA" ascii
        $dns2 = "DnsQueryW" ascii
        $dns3 = "DnsQuery_A" ascii
        $dns4 = "DnsQuery_W" ascii
        $dns5 = "dns_query" ascii
        $b64  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
    condition:
        any of ($dns1, $dns2, $dns3, $dns4, $dns5) and $b64
}

rule C2_TorOnion
{
    meta:
        description = "Communication C2 via Tor (.onion)"
        severity     = "critical"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/ nocase
    condition:
        $onion
}

rule C2_Beaconing_Pattern
{
    meta:
        description = "Pattern de beaconing — Sleep + HTTP loop"
        severity     = "high"
    strings:
        $sleep1 = "Sleep" ascii
        $sleep2 = "SleepEx" ascii
        $sleep3 = "NtDelayExecution" ascii
        $http1  = "InternetOpenA" ascii
        $http2  = "InternetOpenW" ascii
        $http3  = "WinHttpOpen" ascii
        $http4  = "HttpSendRequestA" ascii
        $http5  = "WinHttpSendRequest" ascii
    condition:
        any of ($sleep1, $sleep2, $sleep3) and
        any of ($http1, $http2, $http3, $http4, $http5)
}

rule C2_PythonC2
{
    meta:
        description = "C2 basé sur Python (python-requests User-Agent)"
        severity     = "high"
    strings:
        $ua = "python-requests" ascii
        $ua2 = "python-urllib" ascii
    condition:
        any of them
}

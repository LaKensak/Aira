/*
    AIRA — Règles YARA pour fichiers WAR / Java
    Détection de webshells, backdoors, exploits Java connus.
*/

rule Java_ClassFile_Magic
{
    meta:
        description = "Java class file (CAFEBABE magic)"
        category = "java"
        severity = "info"
    condition:
        uint32be(0) == 0xCAFEBABE
}

rule JSP_Webshell_RuntimeExec
{
    meta:
        description = "JSP webshell - Runtime.exec()"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "Runtime.getRuntime().exec(" ascii nocase
        $s2 = "getRuntime().exec(" ascii
        $s3 = "<%"
    condition:
        $s3 and ($s1 or $s2)
}

rule JSP_Webshell_ProcessBuilder
{
    meta:
        description = "JSP webshell - ProcessBuilder command execution"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "ProcessBuilder" ascii
        $s2 = "getParameter" ascii
        $s3 = ".start()" ascii
    condition:
        all of them
}

rule JSP_Webshell_ClassLoader
{
    meta:
        description = "JSP webshell via ClassLoader - dynamic class loading"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "defineClass" ascii
        $s2 = "ClassLoader" ascii
        $s3 = "getParameter" ascii
    condition:
        2 of them
}

rule JSP_Webshell_ScriptEngine
{
    meta:
        description = "JSP webshell using ScriptEngine for code evaluation"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "ScriptEngineManager" ascii
        $s2 = ".eval(" ascii
        $s3 = "getParameter" ascii
    condition:
        $s1 and ($s2 or $s3)
}

rule JSP_Webshell_Reflection
{
    meta:
        description = "JSP webshell using Java reflection"
        category = "webshell"
        severity = "high"
    strings:
        $s1 = "Class.forName" ascii
        $s2 = "getMethod" ascii
        $s3 = "invoke" ascii
        $s4 = "getParameter" ascii
    condition:
        3 of them
}

rule Java_Deserialization_Gadget
{
    meta:
        description = "Java deserialization gadget chain indicators"
        category = "exploit"
        severity = "critical"
    strings:
        $s1 = "ObjectInputStream" ascii
        $s2 = "readObject" ascii
        $s3 = "InvokerTransformer" ascii
        $s4 = "ChainedTransformer" ascii
        $s5 = "ConstantTransformer" ascii
        $s6 = "LazyMap" ascii
        $s7 = "CommonsCollections" ascii
        $s8 = "ysoserial" ascii
    condition:
        ($s1 and $s2) and any of ($s3, $s4, $s5, $s6, $s7, $s8)
}

rule Java_JNDI_Injection
{
    meta:
        description = "JNDI injection indicators (Log4Shell vector)"
        category = "exploit"
        severity = "critical"
    strings:
        $s1 = "InitialContext" ascii
        $s2 = "lookup" ascii
        $s3 = "ldap://" ascii nocase
        $s4 = "rmi://" ascii nocase
        $s5 = "jndi:" ascii nocase
        $s6 = "${jndi:" ascii nocase
    condition:
        ($s1 and $s2) or any of ($s3, $s4, $s5, $s6)
}

rule Java_BCEL_ClassLoader
{
    meta:
        description = "BCEL ClassLoader exploit (Fastjson, etc.)"
        category = "exploit"
        severity = "critical"
    strings:
        $s1 = "com.sun.org.apache.bcel" ascii
        $s2 = "createClass" ascii
        $s3 = "$$BCEL$$" ascii
    condition:
        any of them
}

rule Known_Webshell_Behinder
{
    meta:
        description = "Behinder (冰蝎) Java webshell"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "behinder" ascii nocase
        $s2 = "e45e329feb5d925b" ascii
        $s3 = "AES" ascii
        $s4 = "javax.crypto.Cipher" ascii
        $s5 = "defineClass" ascii
    condition:
        $s1 or ($s2) or ($s3 and $s4 and $s5)
}

rule Known_Webshell_Godzilla
{
    meta:
        description = "Godzilla (哥斯拉) Java webshell"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "godzilla" ascii nocase
        $s2 = "xc" ascii
        $s3 = "pass" ascii
        $s4 = "javax.crypto" ascii
        $s5 = "ClassLoader" ascii
    condition:
        $s1 or ($s2 and $s3 and $s4 and $s5)
}

rule Known_Webshell_AntSword
{
    meta:
        description = "AntSword Java webshell"
        category = "webshell"
        severity = "critical"
    strings:
        $s1 = "antsword" ascii nocase
        $s2 = "ant_" ascii nocase
    condition:
        any of them
}

rule Java_Reverse_Shell
{
    meta:
        description = "Java reverse shell pattern"
        category = "backdoor"
        severity = "critical"
    strings:
        $s1 = "java.net.Socket" ascii
        $s2 = "/bin/sh" ascii
        $s3 = "cmd.exe" ascii
        $s4 = "getOutputStream" ascii
        $s5 = "getInputStream" ascii
    condition:
        $s1 and ($s2 or $s3) and ($s4 or $s5)
}

rule Java_XXE_Indicators
{
    meta:
        description = "XXE (XML External Entity) attack indicators"
        category = "exploit"
        severity = "high"
    strings:
        $s1 = "<!ENTITY" ascii nocase
        $s2 = "SYSTEM" ascii
        $s3 = "file:///" ascii
        $s4 = "expect://" ascii
        $s5 = "php://filter" ascii
        $s6 = "DocumentBuilderFactory" ascii
    condition:
        ($s1 and $s2 and $s3) or $s4 or $s5 or ($s6 and $s3)
}

rule Java_Expression_Language_Injection
{
    meta:
        description = "Expression Language / Template injection"
        category = "exploit"
        severity = "high"
    strings:
        $s1 = "${" ascii
        $s2 = "T(java.lang.Runtime)" ascii
        $s3 = "getRuntime" ascii
        $s4 = "ELProcessor" ascii
        $s5 = "SpelExpressionParser" ascii
    condition:
        ($s1 and $s2 and $s3) or $s4 or $s5
}

rule Java_SQL_Injection_Pattern
{
    meta:
        description = "Potential SQL injection in Java code"
        category = "vulnerability"
        severity = "high"
    strings:
        $s1 = "createStatement" ascii
        $s2 = "executeQuery" ascii
        $s3 = "\" + " ascii
        $s4 = "getParameter" ascii
        $s5 = "SELECT " ascii nocase
        $s6 = "' OR '" ascii nocase
    condition:
        ($s1 and $s2 and $s4) or ($s5 and $s3 and $s4) or $s6
}

rule Java_Hardcoded_Credentials
{
    meta:
        description = "Hardcoded credentials in Java code"
        category = "secret"
        severity = "high"
    strings:
        $s1 = /password\s*=\s*"[^"]{3,}"/ ascii nocase
        $s2 = /secret[_-]?key\s*=\s*"[^"]{3,}"/ ascii nocase
        $s3 = /api[_-]?key\s*=\s*"[^"]{3,}"/ ascii nocase
        $s4 = /jdbc:[a-z]+:\/\/[^\s"]+:[^\s"]+@/ ascii nocase
        $s5 = "BEGIN RSA PRIVATE KEY" ascii
        $s6 = "BEGIN PRIVATE KEY" ascii
    condition:
        any of them
}

rule Java_Crypto_Weak
{
    meta:
        description = "Weak cryptography usage in Java"
        category = "vulnerability"
        severity = "medium"
    strings:
        $s1 = "DES/ECB" ascii
        $s2 = "DESede" ascii
        $s3 = "MD5" ascii
        $s4 = "SHA-1" ascii
        $s5 = "Cipher.getInstance(\"DES\")" ascii
        $s6 = "ECB/PKCS5Padding" ascii
        $s7 = "SecureRandom()" ascii
    condition:
        2 of them
}

rule Java_Serialized_Object
{
    meta:
        description = "Serialized Java object (ACED magic bytes)"
        category = "deserialization"
        severity = "high"
    condition:
        uint16be(0) == 0xACED
}

rule WAR_Suspicious_Structure
{
    meta:
        description = "WAR file with suspicious structure (shell scripts, executables)"
        category = "suspicious"
        severity = "high"
    strings:
        $s1 = "#!/bin/sh" ascii
        $s2 = "#!/bin/bash" ascii
        $s3 = { 4D 5A 90 00 }
        $s4 = { 7F 45 4C 46 }
    condition:
        uint32be(0) == 0x504B0304 and any of ($s1, $s2, $s3, $s4)
}

rule Log4Shell_Payload
{
    meta:
        description = "Log4Shell (CVE-2021-44228) payload pattern"
        category = "exploit"
        severity = "critical"
    strings:
        $s1 = "${jndi:ldap://" ascii nocase
        $s2 = "${jndi:rmi://" ascii nocase
        $s3 = "${jndi:dns://" ascii nocase
        $s4 = "${jndi:iiop://" ascii nocase
        $s5 = "${${lower:j}" ascii nocase
        $s6 = "${${upper:j}" ascii nocase
        $s7 = "${${::-j}" ascii nocase
    condition:
        any of them
}

rule Spring4Shell_Indicator
{
    meta:
        description = "Spring4Shell (CVE-2022-22965) indicators"
        category = "exploit"
        severity = "critical"
    strings:
        $s1 = "class.module.classLoader" ascii
        $s2 = "tomcatwar" ascii nocase
        $s3 = "spring-webmvc" ascii
        $s4 = "AbstractHandlerMapping" ascii
    condition:
        $s1 or ($s2 and ($s3 or $s4))
}

# Webshell Detection: PHP, ASPX, and JSP

Detects common webshell patterns across PHP, ASPX, and JSP files. Webshells provide persistent remote access to web servers. Attackers upload them after exploiting a web application vulnerability and use them for command execution, file operations, and lateral movement into the internal network.

## ATT&CK

- **Technique:** T1505.003. Server Software Component: Web Shell
- **Tactic:** Persistence

## Severity

**Critical.** A webshell on a production web server is persistent remote access. The attacker can execute arbitrary commands on the server at any time.

## Rule

```yara
rule Webshell_PHP_Generic
{
    meta:
        author = "Ridgeline Cyber"
        description = "Detects common PHP webshell patterns including eval, system, and obfuscation"
        date = "2025-05-25"
        severity = "critical"
        mitre_attack = "T1505.003"
        filetype = "php"

    strings:
        // Direct command execution
        $exec1 = "system($_" ascii nocase
        $exec2 = "exec($_" ascii nocase
        $exec3 = "passthru($_" ascii nocase
        $exec4 = "shell_exec($_" ascii nocase
        $exec5 = "popen($_" ascii nocase
        $exec6 = "proc_open(" ascii nocase

        // Eval with user input
        $eval1 = "eval($_POST" ascii nocase
        $eval2 = "eval($_GET" ascii nocase
        $eval3 = "eval($_REQUEST" ascii nocase
        $eval4 = "eval(base64_decode" ascii nocase
        $eval5 = "assert($_" ascii nocase
        $eval6 = "eval(gzinflate" ascii nocase
        $eval7 = "eval(str_rot13" ascii nocase

        // Obfuscation patterns
        $obf1 = "chr(ord(" ascii
        $obf2 = "str_replace" ascii
        $obf3 = /\$[a-z]{1,3}\s*=\s*['"](e|ev|eva|eval)['"]/ ascii
        $obf4 = "base64_decode(base64_decode" ascii
        $obf5 = "gzuncompress(base64_decode" ascii

        // Known webshell signatures
        $ws1 = "c99shell" ascii nocase
        $ws2 = "r57shell" ascii nocase
        $ws3 = "WSO " ascii
        $ws4 = "b374k" ascii nocase
        $ws5 = "FilesMan" ascii
        $ws6 = "AnonymousFox" ascii

    condition:
        filesize < 1MB and
        (any of ($exec*) and any of ($eval*)) or
        (any of ($eval*) and any of ($obf*)) or
        any of ($ws*)
}

rule Webshell_ASPX_Generic
{
    meta:
        author = "Ridgeline Cyber"
        description = "Detects ASPX webshell patterns including Process.Start and command execution"
        date = "2025-05-25"
        severity = "critical"
        mitre_attack = "T1505.003"
        filetype = "aspx"

    strings:
        // Command execution
        $exec1 = "Process.Start" ascii
        $exec2 = "ProcessStartInfo" ascii
        $exec3 = "cmd.exe" ascii
        $exec4 = "/c " ascii
        $exec5 = "powershell" ascii nocase

        // Request parameter handling
        $req1 = "Request.Form" ascii
        $req2 = "Request.QueryString" ascii
        $req3 = "Request.Item" ascii
        $req4 = "Request[" ascii

        // File operations
        $file1 = "File.WriteAllBytes" ascii
        $file2 = "File.WriteAllText" ascii
        $file3 = "StreamWriter" ascii
        $file4 = "FileStream" ascii

        // Known ASPX shells
        $ws1 = "JspSpy" ascii
        $ws2 = "devilzShell" ascii
        $ws3 = "awen asp" ascii nocase
        $ws4 = "SharPyShell" ascii

        // Compilation and reflection
        $refl1 = "Assembly.Load" ascii
        $refl2 = "CompileAssemblyFromSource" ascii
        $refl3 = "Activator.CreateInstance" ascii

    condition:
        filesize < 1MB and
        (any of ($exec*) and any of ($req*)) or
        (any of ($refl*) and any of ($req*)) or
        (any of ($file*) and any of ($req*)) or
        any of ($ws*)
}

rule Webshell_JSP_Generic
{
    meta:
        author = "Ridgeline Cyber"
        description = "Detects JSP webshell patterns including Runtime.exec and command execution"
        date = "2025-05-25"
        severity = "critical"
        mitre_attack = "T1505.003"
        filetype = "jsp"

    strings:
        $exec1 = "Runtime.getRuntime().exec" ascii
        $exec2 = "ProcessBuilder" ascii
        $exec3 = "getParameter" ascii
        $exec4 = "/bin/sh" ascii
        $exec5 = "/bin/bash" ascii
        $exec6 = "cmd /c" ascii nocase

        // Request handling + execution combo
        $req1 = "request.getParameter" ascii
        $req2 = "getInputStream" ascii

        // Known JSP shells
        $ws1 = "JspSpy" ascii
        $ws2 = "cmdjsp" ascii
        $ws3 = "jspFileBrowser" ascii
        $ws4 = "Godzilla" ascii

    condition:
        filesize < 1MB and
        (any of ($exec*) and any of ($req*)) or
        any of ($ws*)
}
```

## Deployment

```bash
# Scan web roots
yara -r webshells.yar /var/www/html/
yara -r webshells.yar C:\inetpub\wwwroot\
yara -r webshells.yar /opt/tomcat/webapps/

# Scheduled scan (cron)
0 */6 * * * yara -r /opt/yara/webshells.yar /var/www/ >> /var/log/yara-webshell.log 2>&1
```

## False Positives

1. **Legitimate admin panels.** Some CMS admin files contain eval/exec patterns for plugin management. Baseline your web root and exclude known files by hash.
2. **Development files.** Test scripts with exec calls during development. Scan production web roots only.
3. **Security testing tools.** Authorized penetration testing may deploy test webshells. Verify against engagement schedules.

## Learn More

- [Incident Response: Web Server Compromise](https://ridgelinecyber.com/training/courses/practical-ir/). webshell discovery and containment
- [YARA: Rule Development](https://ridgelinecyber.com/training/courses/yara-rule-writing/). writing detection rules for web artifacts

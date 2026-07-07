/*
 * sacrificial_dlls.h -- Curated list of Windows DLLs suitable for module stomping
 *
 * Selection criteria:
 *   - Large .text section (must be >= shellcode size)
 *   - Microsoft-signed (thread start address looks legitimate)
 *   - Not commonly hooked by EDR (avoids detection via hook verification)
 *   - Loadable without side effects (no complex DllMain initialization)
 *
 * .text sizes are approximate and vary by Windows version (values from
 * Windows 10 21H2 / Windows 11 22H2). Always verify at runtime.
 *
 * Categories:
 *   TIER_ALWAYS_PRESENT  -- Guaranteed on all Windows installs
 *   TIER_COMMONLY_LOADED -- Present on most systems, may already be loaded
 *   TIER_LARGE_TEXT      -- Very large .text sections for big payloads
 */

#ifndef SACRIFICIAL_DLLS_H
#define SACRIFICIAL_DLLS_H

/* ============================================================================
 * TIER 1: ALWAYS PRESENT
 * These DLLs ship with every Windows installation. Safe to load anywhere.
 * ============================================================================ */

/*
 * dbghelp.dll
 * .text size: ~800 KB
 * Notes: Debugging support library. Rarely hooked by EDR. Not typically
 *        loaded by default, so loading it does not look suspicious in most
 *        contexts (debuggers, crash handlers load it routinely).
 *        RECOMMENDED as default sacrificial DLL.
 */
#define SACRIFICIAL_DBGHELP       "dbghelp.dll"
#define SACRIFICIAL_DBGHELP_TEXT  (800 * 1024)

/*
 * msvcp140.dll (or msvcp_win.dll on newer builds)
 * .text size: ~500 KB
 * Notes: C++ standard library runtime. Very commonly loaded by applications.
 *        EDRs generally do not hook this. Loading it is completely normal.
 */
#define SACRIFICIAL_MSVCP140      "msvcp140.dll"
#define SACRIFICIAL_MSVCP140_TEXT (500 * 1024)

/*
 * xpsservices.dll
 * .text size: ~900 KB
 * Notes: XPS document services. Rarely loaded, large .text. Good for bigger
 *        payloads. Not monitored by EDR.
 */
#define SACRIFICIAL_XPSSERVICES      "xpsservices.dll"
#define SACRIFICIAL_XPSSERVICES_TEXT  (900 * 1024)

/*
 * winspool.drv
 * .text size: ~350 KB
 * Notes: Print spooler client interface. Present on all systems.
 *        Not commonly hooked.
 */
#define SACRIFICIAL_WINSPOOL      "winspool.drv"
#define SACRIFICIAL_WINSPOOL_TEXT (350 * 1024)

/*
 * amsi.dll
 * .text size: ~40 KB (small -- only for tiny payloads)
 * Notes: Antimalware Scan Interface. HEAVILY MONITORED by EDR. Loading this
 *        DLL will trigger scrutiny. Included for completeness only.
 *        DO NOT USE unless you have a specific reason.
 */
#define SACRIFICIAL_AMSI          "amsi.dll"
#define SACRIFICIAL_AMSI_TEXT     (40 * 1024)
/* WARNING: EDR-monitored. Avoid. */


/* ============================================================================
 * TIER 2: COMMONLY LOADED
 * Present on most systems. May already be in the process, which means you
 * need to load a second copy from a different path or skip to another DLL.
 * ============================================================================ */

/*
 * colorui.dll
 * .text size: ~250 KB
 * Notes: Color management UI. Rarely loaded by applications.
 *        Not hooked. Good mid-size option.
 */
#define SACRIFICIAL_COLORUI      "colorui.dll"
#define SACRIFICIAL_COLORUI_TEXT (250 * 1024)

/*
 * devobj.dll
 * .text size: ~200 KB
 * Notes: Device object support. Present on all systems, rarely loaded
 *        directly by applications. Not hooked.
 */
#define SACRIFICIAL_DEVOBJ      "devobj.dll"
#define SACRIFICIAL_DEVOBJ_TEXT (200 * 1024)

/*
 * dui70.dll
 * .text size: ~700 KB
 * Notes: DirectUI engine. Good size, not commonly hooked.
 *        Loaded by Explorer and some UI components.
 */
#define SACRIFICIAL_DUI70      "dui70.dll"
#define SACRIFICIAL_DUI70_TEXT (700 * 1024)

/*
 * mshtml.dll
 * .text size: ~6 MB
 * Notes: Trident HTML engine. Extremely large .text section. Good for
 *        very large payloads. However, loading it has side effects
 *        (COM initialization, etc.) and it is a complex DLL.
 *        Use only when you need the space.
 */
#define SACRIFICIAL_MSHTML      "mshtml.dll"
#define SACRIFICIAL_MSHTML_TEXT (6 * 1024 * 1024)


/* ============================================================================
 * TIER 3: LARGE .TEXT (for big payloads)
 * When your shellcode exceeds 500 KB, use one of these.
 * ============================================================================ */

/*
 * chakra.dll
 * .text size: ~4 MB
 * Notes: Legacy JavaScript engine (Edge Legacy / IE). Very large .text.
 *        Not commonly loaded in modern applications, so loading it is
 *        slightly unusual but not alarming. Not hooked by EDR.
 *        RECOMMENDED for large payloads.
 */
#define SACRIFICIAL_CHAKRA      "chakra.dll"
#define SACRIFICIAL_CHAKRA_TEXT (4 * 1024 * 1024)

/*
 * mfc140u.dll
 * .text size: ~3.5 MB
 * Notes: MFC runtime (Unicode). Large .text, commonly present.
 *        Not hooked. Good option for large payloads.
 */
#define SACRIFICIAL_MFC140U      "mfc140u.dll"
#define SACRIFICIAL_MFC140U_TEXT (3500 * 1024)

/*
 * d3d11.dll
 * .text size: ~1.5 MB
 * Notes: Direct3D 11 runtime. Very commonly loaded by games and GPU
 *        applications. Not hooked by EDR. Loading it is completely normal
 *        on systems with a GPU.
 */
#define SACRIFICIAL_D3D11      "d3d11.dll"
#define SACRIFICIAL_D3D11_TEXT (1500 * 1024)

/*
 * windows.storage.dll
 * .text size: ~3 MB
 * Notes: WinRT storage APIs. Large .text, present on Windows 10+.
 *        May have initialization side effects.
 */
#define SACRIFICIAL_WINSTORAGE      "windows.storage.dll"
#define SACRIFICIAL_WINSTORAGE_TEXT  (3 * 1024 * 1024)


/* ============================================================================
 * EDR MONITORING NOTES
 *
 * DLLs that EDRs commonly hook or monitor (AVOID for stomping):
 *   - ntdll.dll       -- Syscall layer, heavily hooked
 *   - kernel32.dll    -- Core API, heavily hooked
 *   - kernelbase.dll  -- Core API, heavily hooked
 *   - amsi.dll        -- AMSI, monitored for tampering
 *   - clr.dll         -- .NET runtime, monitored for .NET abuse
 *   - user32.dll      -- Often hooked for API monitoring
 *   - advapi32.dll    -- Security APIs, sometimes hooked
 *   - ws2_32.dll      -- Winsock, sometimes monitored for network calls
 *
 * DLLs that EDRs generally IGNORE (prefer for stomping):
 *   - dbghelp.dll     -- Debug support
 *   - colorui.dll     -- Color management
 *   - chakra.dll      -- Legacy JS engine
 *   - xpsservices.dll -- XPS support
 *   - dui70.dll       -- DirectUI
 *   - mfc*.dll        -- MFC runtimes
 *   - d3d*.dll        -- DirectX runtimes
 *   - msvcp*.dll      -- C++ runtimes
 * ============================================================================ */


/* ============================================================================
 * DEFAULT SELECTION
 *
 * If the operator does not specify a sacrificial DLL, use this default.
 * dbghelp.dll is recommended: always present, ~800 KB .text, not hooked,
 * and loading it is normal for any application that handles crash dumps.
 * ============================================================================ */

#ifndef SACRIFICIAL_DLL
#define SACRIFICIAL_DLL      SACRIFICIAL_DBGHELP
#define SACRIFICIAL_DLL_TEXT SACRIFICIAL_DBGHELP_TEXT
#endif

#endif /* SACRIFICIAL_DLLS_H */

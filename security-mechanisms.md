# General Security Mechanisms

## Core Anti-Cheat Philosophy (Circa 2016)

The 2016 Roblox client's anti-cheat strategy appears to be rooted in several key principles:

*   **Defense in Depth:** Employing multiple, varied detection mechanisms (control flow, signatures, memory integrity, behavioral heuristics) to increase the likelihood of catching diverse exploits.
*   **Client-Side Authority with Server-Side Verification:** While many checks ran on the client, mechanisms like Fuzzy Security Tokens aimed to securely report findings to the server, which could then take action.
*   **Obfuscation and Anti-Reverse Engineering:** Extensive use of techniques like code virtualization (VMProtect), string encryption, and self-modifying code (`ReleasePatcher`) to hinder analysis and raise the bar for cheat developers.
*   **Performance Consciousness:** Techniques like incremental hashing in the PMC show an awareness of the need to balance security with client performance.

## Return Check (RetCheck)

Return Check, often abbreviated as RetCheck, is a crucial control-flow integrity (CFI) mechanism. Its primary function is to detect and prevent exploits that tamper with function return addresses stored on the call stack. The call stack is a fundamental data structure that tracks active function calls, and each function call stores a "return address" - the location in memory where execution should resume after the function completes. Exploiters frequently target these return addresses. By overwriting a return address, they can redirect the program's execution flow to arbitrary locations, often to their own malicious code (shellcode) or to chain together existing legitimate code snippets in unintended sequences (Return-Oriented Programming or ROP).

RetCheck diligently monitors these return addresses for any signs of such tampering. If an inconsistency is detected, for instance, if a return address points outside of expected executable code regions (like the `.text` section), or if the instruction preceding the return address doesn't match a valid `call` instruction - it flags this as a violation. Internally, such violations would often be marked with an identifier like **`HATE_RETURN_CHECK`**. This system acts as a critical line of defense against common memory corruption vulnerabilities (e.g., stack buffer overflows) and direct code injection or redirection techniques.

### Implementation Insights

The `checkRbxCaller` template function, as seen in the code, provides a concrete example of how RetCheck was implemented. This function was often `FORCEINLINE`d, meaning the compiler was strongly encouraged to insert its code directly into the calling function. This reduces the overhead of a function call and can also make it slightly harder for attackers to generically hook or bypass `checkRbxCaller` itself, as its code becomes part of many different functions.

The checks performed using the `_ReturnAddress()` intrinsic (a compiler-specific function that provides the return address of the current function) were multi-layered:
1.  **Basic .text Section Check**: It verified that the immediate return address fell within Roblox's own executable code segment (typically the `.text` section). This was often done using a helper function like `isRbxTextAddr`. This is a fundamental check to ensure execution isn't being redirected to data sections or entirely outside the legitimate program code.
2.  **Call Instruction Verification (e.g., `kCallCheckCallArg`)**: For more stringent checks, it examined the machine instruction bytes immediately preceding the return address in memory. For a direct `call imm32` instruction (a common way functions are called), the bytes would encode the relative offset to the called function. RetCheck would compare the expected offset (calculated from the known address of the current function `funcAddress` and the `returnAddress`) against the actual bytes in memory. A mismatch indicates that the call site might have been tampered with or that the return address is not from a legitimate direct call.
3.  **Caller's Caller Validation (e.g., `kCallCheckCallersCode`)**: An extended check could attempt to validate the return address of the *calling* function (i.e., further up the stack). This was achieved using `_AddressOfReturnAddress()` to find where the current function's return address is stored on the stack, then moving further up to find the previous return address. This helps detect more sophisticated attacks that might corrupt multiple stack frames.
4.  **Indirect Call Detection (e.g., `kCallCheckRegCall`)**: A weaker check (`kCallCheckRegCall`) attempted to identify indirect calls (e.g., `call eax` or `call [ecx+edx*4]`). This check looked for specific opcode patterns associated with such calls. These are harder to validate perfectly because the target of the call isn't known until runtime, but flagging unexpected indirect calls could still be valuable.

If any of these checks failed, an `action` function (passed as a template parameter, e.g., `callCheckSetApiFlag`) was invoked to set the corresponding `HATE_` flag, signaling a potential security violation.

### Example Usage
RetCheck calls were embedded directly into security-sensitive functions like `Humanoid::changeState` to validate the caller immediately upon entry, ensuring the function call originated from a legitimate code path.

```cpp
// Example of RetCheck being used in Humanoid::changeState
void Humanoid::changeState(HUMAN::StateType state) {
  // ... function logic ...
  void (Humanoid::*thisFunction)(HUMAN::StateType) = &Humanoid::changeState;
  // Perform RetCheck (basic .text check), flag kChangeStateApiOffset on failure
  checkRbxCaller<kCallCheckCodeOnly, callCheckSetApiFlag<kChangeStateApiOffset>>(reinterpret_cast<void*>((void*&)(thisFunction)));
  // ... rest of function logic ...
}
```

## Signature Check (SigCheck)

Signature Check (SigCheck) searches for known patterns (signatures) associated with cheating tools or modifications within the game's process memory or environment. This includes scanning for unique strings (e.g., "speedhack", "d3dhook", "Cheat Engine"), byte sequences in code, or specific loaded module names (e.g., `SbieDll.dll`). To hinder static analysis, searched strings or patterns were often obfuscated and only decrypted immediately before use. It also extended to checking the integrity of critical system functions to detect API hooking.

### Implementation Insights

1.  **Cheat Tool String Detection**: Obfuscated strings like `"speedhack"` and `"d3dhook"` were stored as byte arrays and decrypted at runtime (`decryptCeDllStrings`) before searching memory.
2.  **Tool Module Detection**: Checks like `isSandboxie` looked for loaded modules (e.g., `SbieDll.dll`) using `GetModuleHandle`, with the module name itself being obfuscated and the check potentially virtualized (`VMProtectBeginMutation`).
3.  **NT API Name Obfuscation**: Functions like `cmpNtQueryVirtualMemory` and `cmpNtGetContextThread` perform obfuscated string comparisons to find specific NT API function addresses, ensuring the correct functions are located even if simple string searches are bypassed.
4.  **NT API Hooking Detection (`NtApiCaller`)**: This class verifies the integrity of critical Windows API functions (`NtQueryVirtualMemory`, `NtGetContextThread`) frequently targeted by hooks. It checks if the function's prologue matches expected bytes (`funcMem[0] == 0xB8`) and compares a hash of the function's body (`hashFeed`, `checkHash`) against an expected hash derived from a template function (`ZwFilterToken`, `ZwLoadKey`). Failures indicate potential API hooking and trigger specific `kNtApi...` flags.

## Memory Check (Program Memory Checker - PMC)

The Program Memory Checker (PMC) was a sophisticated system responsible for detecting unauthorized modifications to the game's memory space at runtime. It went beyond simple checks by employing incremental hashing of various critical memory sections, integrity checks on core system functions used by the checker itself, nonce-based randomization, and specific countermeasures against known hacking techniques like Stealthedit. Violations were meticulously tracked using specific failure flags (`Hasher::HashFailures`).

### Implementation Insights

The `ProgramMemoryChecker` class and associated code reveal a multi-faceted approach:
1.  **Sectioned Memory Hashing**: PMC didn't just hash the entire `.text` section. It divided memory into multiple logical regions (`Hasher::HashSection`) including split `.text` sections (`kGoldHashStart`, `kGoldHashEnd`), `.rdata` (`kRdataHash`), VMProtect sections (`kVmpPlainHash`, `kVmpMutantHash`, `kVmp0MiscHash`, `kVmp1MiscHash`), the Import Address Table (`kIatHash`), and even sections from external DLLs like `winmm.dll` (`kMiscHash`) and the MSVC runtime (`kMsvcHash`). This provided more granular detection.
2.  **Incremental Hashing (`step()`)**: To avoid performance spikes, the hashing was performed incrementally over time. The `step()` function processed a small chunk (`bytesPerStep`) of memory in each call, cycling through the defined `scanningRegions`. This distributed the CPU load. The XXHash algorithm (`XXH32`) was used for its speed.
3.  **Hashing Obfuscation (`modifyArg`)**: The input bytes fed into the hash function were slightly modified based on their memory address using the `modifyArg` templates (`*(uint*)p + p`, `*(uint*)p - p`, etc.). This minor obfuscation aimed to make it harder for exploiters to predict or replicate the exact hash value without running the original code.
4.  **Nonce Integration**: A 32-bit nonce (`pmcHash.nonce`) was incorporated into the hashing process (`kGoldHashRot`, `kNonGoldHashRot`). This nonce was periodically incremented (`kPmcNonceGoodInc`), adding a time-varying element to some hash calculations. An internal integrity check (comparing `expectedCurrentMemory` vs `stackCurrentMemory` in `step()`) could cause the nonce to increment differently (`kPmcNonceBadInc`) if stack tampering was suspected, subtly altering future hashes.
5.  **Structure Hashing (`hashScanningRegions`)**: Beyond hashing the memory *content*, PMC also calculated a hash of the *metadata* describing the scanned regions (addresses, sizes, configuration flags, and even the resulting hashes themselves). This detected attempts to tamper with the checker's configuration.
6.  **Stealthedit Detection (`areMemoryPagePermissionsSetupForHacking`)**: This function explicitly checked for the "Stealthedit" technique. It used `VirtualQuery` on the `.text` section to verify that its memory protection was set to executable (`PAGE_EXECUTE_READ`) and that the region size matched expectations. Pages unexpectedly marked non-executable or split regions were flagged.
7.  **NT API Integrity (`NtApiCaller`)**: As described under SigCheck, this crucial component ensured the integrity of `NtQueryVirtualMemory` and `NtGetContextThread`, preventing exploits from blinding the PMC by hooking the very functions it relied on to inspect memory and threads.
8.  **Specific Function/Data Integrity**: Included checks for specific, sensitive code (`updateHsceHash` hashing `HumanoidState::computeEvent`) and data (`checkG3dConsts` verifying G3D math constants weren't tampered with).
9.  **VMP Integration**: Sensitive parts of the PMC logic were frequently wrapped in `VMProtectBeginMutation`/`VMProtectEnd`, indicating heavy use of code virtualization/mutation for protection. `protectVmpSections` was called to change VMP code sections to Read+Execute after initialization, preventing runtime patching.
10. **Failure Reporting**: A detailed set of flags (`Hasher::HashFailures`) like `kGoldHashFail`, `kNonceFail`, `kVmpMutantHashFail`, etc., allowed for precise reporting of which check failed, likely feeding into the Fuzzy Security Token system.

## Fuzzy Security Tokens

Fuzzy Security Tokens represent an anti-tampering mechanism for reporting client-side security events (like detected cheats or flags) to the server. Instead of sending raw flag data, which could be easily intercepted and spoofed by an exploiter, the client encrypts the flags into a token using an algorithm like TEA (Tiny Encryption Algorithm). The "fuzzy" aspect comes from the server-side processing: when the server receives and decrypts the token, there's a built-in probabilistic chance that some of the 'set' flags (represented as '1' bits) might be interpreted as 'unset' ('0' bits). The comment suggests a 50% chance per flag bit per transmission. This makes it difficult for an exploiter to craft a "perfectly clean" token, because even if they suppress a flag on the client, repeated detections triggering re-transmissions increase the likelihood that the flag eventually gets successfully reported to the server. The server maintains state (`lastTag`) to potentially compare subsequent tokens and can be configured to ignore certain flags (`ignoreFlags`).

### Implementation Insights

The code defines `ClientFuzzySecurityToken` and `ServerFuzzySecurityToken` classes. The client side likely aggregates detected `HATE_` flags, encrypts them using `teaEncrypt` (presumably TEA), and sends the resulting `unsigned long long` token. Global instances like `sendStatsToken` and `apiToken` suggest these tokens were embedded within regular network packets like statistics updates or API call acknowledgments. On the server, the `decrypt` method would use `teaDecrypt`, incorporating the probabilistic flag dropping logic. A '1' bit in the decrypted value corresponding to a specific `HATE_` flag indicates a potential cheat detection reported by the client.

---

## Lua Environment Hardening

Given Roblox's reliance on Lua (previously Lua 5.1, now Luau), securing the Lua environment is critical. This involved modifying the Lua interpreter to prevent exploits targeting the scripting engine, such as patching standard functions and adding checks at the C++/Lua boundary.

### Implementation Insights

```cpp
// Modification to luaB_newproxy to disable GC finalizers
static int luaB_newproxy (lua_State *L) {
	// ... setup ...
	Udata* u = (Udata*) lua_newuserdata(L, 0);
	u--; // Go to header
	u->uv.may_gc = false; // ROBLOX: Disable GC hook for security
	// ... rest of function ...
}

// Modification to f_Ccall (Lua's C function execution wrapper)
static void f_Ccall (lua_State *L, void *ud) {
	// ... setup ...
	// ROBLOX: Inserted check at the C call boundary
	lua_chk_ptr_rblx(_ReturnAddress(), lua_vmhooked_handler, L); /* added for exploit */
	// ... original Lua call logic ...
}
```

The reverse engineered code reveals specific modifications made to the Lua 5.1 codebase for security:
1.  **Garbage Collector (GC) Hardening (`luaB_newproxy`)**: The standard `luaB_newproxy` function creates Lua userdata objects. Roblox modified this function to explicitly set the `may_gc` flag to `false` on the created userdata header. This prevents the Lua garbage collector from calling potential `__gc` metamethods (finalizers) associated with these proxies. The comment explains this is crucial because the GC handler might run with elevated privileges (non-sandboxed), and allowing user-controlled Lua code (via `__gc` metamethods) to execute in that context would be a significant security risk.
2.  **C Function Call Protection (`f_Ccall`)**: The `f_Ccall` function is part of Lua's internal mechanism for executing C functions called from Lua. Roblox inserted a custom check, `lua_chk_ptr_rblx(_ReturnAddress(), lua_vmhooked_handler, L)`, directly into this pathway. This check likely performs a Return Check (`_ReturnAddress()`) specifically tailored for the Lua C boundary. If tampering is detected, it might invoke a specific handler (`lua_vmhooked_handler`) to manage the violation. This protects against exploits that might try to corrupt the state or control flow during the transition from Lua execution to a native C function. The comment explicitly states this was "added for exploit" mitigation. Since Roblox now maintains its own Luau VM, implementing such hardening measures is likely more streamlined.

## General Anti-Tampering and Environment Checks

Roblox employed several other techniques to detect tampering, hinder reverse engineering, and ensure the game ran in an expected environment. This included leveraging OS security features, detecting API hooks, protecting critical constants, and importantly, performing pre-release patching of the executable itself to embed runtime-specific security data.

### Implementation Insights

1.  **Release Patcher (`ReleasePatcher.cpp`)**: This crucial step occurred *after* the main build but *before* distribution.
    *   **Purpose**: To embed security data specific to that exact build (addresses, calculated hashes) directly into the executable, making runtime checks harder to spoof.
    *   **Process (`patchMain`)**: It launched the newly built executable (`RobloxPlayerBeta.exe`) in a *suspended* state (`CREATE_SUSPENDED`). It then analyzed the suspended process's memory layout using Windows APIs (`ReadProcessMemory`, PE header parsing via `getSections`, `getSectionInfo`) to determine the actual runtime addresses and sizes of critical sections (`.text`, `.rdata`, `.vmp0`, `.vmp1`, IAT). It specifically located the VMProtect sections (`getVmpSections`) and the Import Address Table (`getImportThunkSection`) to precisely define regions for the PMC.
    *   **Patching (`createUpdatedExe`)**: It read the original executable file into memory. Using a `SectionMapping` helper, it overwrote specific `volatile const` variables within the `.rdata` section of the *file buffer* (and simultaneously in the *patcher's own memory*) with the determined addresses (`rbxLowerBase`, `rbxUpperBase`, `rbxVmpBase`, etc.) and sizes. It calculated "golden" hashes (`pmc.getLastGoldenHash()`) based on the *actual* memory content of the suspended child process and patched this hash value into `RBX::Security::rbxGoldHash` in the `.rdata` section. It also generated and embedded encrypted, partial memory hashes (`NetPmcChallenge` data, encrypted using `teaEncrypt` and shuffled) used for network-based integrity checks. Finally, it wrote the modified file buffer back to disk (as `.tmp`, likely renamed later).
    *   **`.text` Padding Modification (`addRefsToWcPage`)**: The patcher searched for sequences of padding bytes (`0xCC`) in the `.text` section (often between functions) and replaced some with a `mov dword ptr [addr], eax`-like instruction (`0xA3`) pointing to an anti-writecopy trap function (`RBX::writecopyTrap`). This likely aimed to detect memory modifications or certain debugging techniques that trigger copy-on-write.
    *   **Self-Removal**: The patcher code itself resided in a dedicated `.zero` section, which was zeroed out and had its PE section flags cleared before the final executable was written, effectively removing the patcher from the distributed client.
2.  **Data Execution Prevention (DEP)**: Explicitly enabled using `SetProcessDEPPolicy` to prevent execution of code from data pages.
3.  **ASLR (Address Space Layout Randomization) History**: The code comments indicate ASLR was *disabled* at that time to ensure consistent memory layouts needed for the PMC's hashing, sacrificing randomization for predictable hash values. The `ReleasePatcher` was the mechanism to handle the resulting fixed (but build-specific) addresses.
4.  **API Hooking Detection**: Beyond `NtApiCaller`, the check for `FreeConsole` hooking (comparing prologue bytes) served as another specific API integrity check, intended to annoy cheat developers using console output (lol).
5.  **Code Obfuscation/Protection**: Heavy use of `VMProtectSDK.h` macros (`VMProtectBeginMutation`, `VMProtectEnd`) indicates significant parts of the anti-cheat code were virtualized or mutated. `protectVmpSections` further hardened VMP sections by setting them to Read+Execute.
6.  **Constant Integrity Checks**: Functions like `checkG3dConsts` verified that hardcoded constants (like identity matrices or unit vectors) hadn't been altered in memory.

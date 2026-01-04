import "math"

rule Ransomware_Malrev_Extension_Specific
{
    meta:
        description = "MALREV BY PYRG - Ransomware with .malrev extension"
        author = "Security Analyst"
        severity = "critical"
        confidence = "very_high"
        malware_family = "MALREV"
        attribution = "PYRG"

    strings:
        // Extension .malrev yang hardcoded
        $ext_malrev = ".malrev" ascii
        $ext_bytes = { 2E 6D 61 6C 72 65 76 00 }  // ".malrev\0"

        // AES-GCM functions (minimal untuk konfirmasi)
        $aes1 = "EVP_aes_128_gcm" ascii
        $aes2 = "EVP_EncryptUpdate" ascii

        // Directory traversal
        $dir1 = "opendir" ascii
        $dir2 = "readdir" ascii

    condition:
        uint32(0) == 0x464c457f and
        any of ($ext*) and
        any of ($aes*) and
        all of ($dir*)
}

rule Ransomware_AES_GCM_Directory_Encryption
{
    meta:
        description = "MALREV BY PYRG - AES-GCM directory encryption ransomware"
        author = "Security Analyst"
        severity = "critical"
        confidence = "high"
        malware_family = "MALREV"
        attribution = "PYRG"

    strings:
        // Core encryption behavior (MUST HAVE)
        $aes_gcm = "EVP_aes_128_gcm" ascii
        $encrypt_init = "EVP_EncryptInit_ex" ascii
        $encrypt_update = "EVP_EncryptUpdate" ascii
        $rand = "RAND_bytes" ascii

        // Directory traversal (MUST HAVE untuk ransomware)
        $opendir = "opendir" ascii
        $readdir = "readdir" ascii
        $fstatat = "fstatat" ascii

        // File operations (MUST HAVE)
        $fopen = "fopen" ascii
        $fwrite = "fwrite" ascii
        $fread = "fread" ascii

        // Suspicious: unlink (self-delete atau cleanup)
        $unlink = "unlink" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        // MUST have AES-GCM encryption
        $aes_gcm and $encrypt_init and $encrypt_update and $rand and
        // MUST have directory traversal
        all of ($opendir, $readdir, $fstatat) and
        // MUST have file I/O
        all of ($fopen, $fwrite, $fread) and
        // OPTIONAL but suspicious
        $unlink
}

rule Ransomware_Enc_Dec_Mode_Pattern
{
    meta:
        description = "MALREV BY PYRG - Ransomware with enc/dec command mode"
        author = "Security Analyst"
        severity = "high"
        confidence = "high"
        malware_family = "MALREV"
        attribution = "PYRG"

    strings:
        // Mode selection strings
        $mode_enc = "enc" ascii fullword
        $mode_dec = "dec-" ascii

        // AES-GCM (minimal)
        $aes = "EVP_aes_128_gcm" ascii

        // argc comparison untuk mode selection
        // cmp [argc], 1; je; cmp [argc], 3
        $argc_check = { 83 ?? 01 74 ?? 83 ?? 03 }

        // String comparison for "enc" (cmp byte ptr [rax], 'e')
        $enc_check = { 80 38 65 }  // cmp byte [rax], 0x65 ('e')

        // 16-byte key check (ransomware key length)
        // Removed: too generic, causes slowdown

        // Directory functions
        $dir = "readdir" ascii

    condition:
        uint32(0) == 0x464c457f and
        $aes and
        ($mode_enc or $mode_dec) and
        $argc_check and
        $dir and
        $enc_check
}


rule Ransomware_With_AntiDebug_Confirmation
{
    meta:
        description = "MALREV BY PYRG - Ransomware with anti-debug/VM evasion"
        author = "Security Analyst"
        severity = "high"
        confidence = "medium_high"
        malware_family = "MALREV"
        attribution = "PYRG"

    strings:
        // CORE: Encryption behavior (required)
        $core_aes = "EVP_aes_128_gcm" ascii
        $core_rand = "RAND_bytes" ascii
        $core_dir = "readdir" ascii

        // SECONDARY: Anti-debug (untuk konfirmasi)
        $antidebug_ptrace = "ptrace" ascii
        $antidebug_proc = "/proc/self/status" ascii
        $antidebug_tracer = "TracerPid:" ascii

        // SECONDARY: Container detection (untuk konfirmasi)
        $container_docker = "docker" ascii
        $container_lxc = "lxc" ascii
        $container_containerd = "containerd" ascii

        // SECONDARY: nice(10) pattern
        $nice_pattern = { BF 0A 00 00 00 E8 }

    condition:
        uint32(0) == 0x464c457f and
        // MUST have core encryption
        all of ($core_*) and
        // AND have anti-debug OR container detection
        (
            2 of ($antidebug_*) or
            1 of ($container_*) or
            $nice_pattern
        )
}

rule Ransomware_SelfDelete_Behavior
{
    meta:
        description = "MALREV BY PYRG - Self-delete behavior after execution"
        author = "Security Analyst"
        severity = "high"
        confidence = "high"
        malware_family = "MALREV"
        attribution = "PYRG"
        technique = "T1070.004 - Indicator Removal on Host: File Deletion"

    strings:
        // unlink syscall/function
        $unlink1 = "unlink" ascii
        $unlink2 = "_unlink" ascii

        // _exit after unlink (self-delete pattern)
        $exit1 = "_exit" ascii
        $exit2 = "exit" ascii

        // Pattern: unlink(argv[0]) or unlink(path)
        // mov rdi, [argv] or similar
        $unlink_argv = { 48 8B ?? [0-8] E8 ?? ?? ?? ?? }

        // Pattern: readlink -> unlink (get own path then delete)
        $readlink = "readlink" ascii

        // /proc/self/exe (to get own executable path)
        $proc_self = "/proc/self/exe" ascii

        // Encryption functions (must have untuk confirm ransomware)
        $crypto1 = "EVP_EncryptUpdate" ascii
        $crypto2 = "RAND_bytes" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        // MUST have unlink
        any of ($unlink*) and
        // MUST have exit (cleanup after delete)
        any of ($exit*) and
        // MUST have crypto (confirm ini ransomware, bukan tool biasa)
        any of ($crypto*) and
        // STRONG indicator: readlink + /proc/self/exe (get own path)
        (
            ($readlink and $proc_self) or
            $unlink_argv
        )
}

rule Ransomware_Complete_SelfDelete_Chain
{
    meta:
        description = "MALREV BY PYRG - Complete self-delete chain (readlink->unlink->exit)"
        author = "Security Analyst"
        severity = "critical"
        confidence = "very_high"
        malware_family = "MALREV"
        attribution = "PYRG"
        technique = "T1070.004 - Indicator Removal on Host: File Deletion"

    strings:
        // Step 1: Get own executable path
        $step1_readlink = "readlink" ascii
        $step1_proc = "/proc/self/exe" ascii

        // Step 2: Delete executable
        $step2_unlink = "unlink" ascii

        // Step 3: Exit immediately
        $step3_exit = "_exit" ascii

        // Encryption (confirm ransomware)
        $crypto = "EVP_aes_128_gcm" ascii

    condition:
        uint32(0) == 0x464c457f and
        // MUST have complete chain
        $step1_readlink and $step1_proc and
        $step2_unlink and
        $step3_exit and
        // MUST be ransomware
        $crypto
}


rule Ransomware_Encrypted_File_Malrev
{
    meta:
        description = "MALREV BY PYRG - Encrypted file with .malrev extension"
        author = "Security Analyst"
        file_type = "encrypted_data"
        malware_family = "MALREV"
        attribution = "PYRG"

    condition:
        // File name ends with .malrev
        // Note: YARA tidak bisa check filename directly, ini untuk file content

        // Ciri-ciri file terenkripsi:
        // 1. High entropy (>7.5)
        // 2. Size > 34 bytes (header + tag)
        // 3. Bukan executable
        uint32(0) != 0x464c457f and  // NOT ELF
        filesize > 34 and
        filesize < 100MB and
        math.entropy(0, filesize) > 7.5
}


rule Ransomware_Master_Smart_Detection
{
    meta:
        description = "MALREV BY PYRG - Master detection rule with smart logic"
        author = "Security Analyst"
        severity = "critical"
        confidence = "high"
        malware_family = "MALREV"
        attribution = "PYRG"

    condition:
        // Prioritas 1: VERY SPECIFIC (extension .malrev)
        Ransomware_Malrev_Extension_Specific

        or

        // Prioritas 2: CORE BEHAVIOR (AES-GCM + Directory encryption)
        Ransomware_AES_GCM_Directory_Encryption

        or

        // Prioritas 3: MODE PATTERN (enc/dec commands)
        Ransomware_Enc_Dec_Mode_Pattern

        or

        // Prioritas 4: BEHAVIOR + ANTI-DEBUG (kombinasi)
        Ransomware_With_AntiDebug_Confirmation

        or

        // Prioritas 5: SELF-DELETE BEHAVIOR
        Ransomware_SelfDelete_Behavior

        or

        // Prioritas 6: COMPLETE CHAIN
        Ransomware_Complete_SelfDelete_Chain
}


rule NOT_Normal_System_Binary
{
    meta:
        description = "Filter: Bukan system binary yang normal"

    strings:
        // Normal system binary indicators (exclude these)
        $sys1 = "GNU" ascii
        $sys2 = "GCC:" ascii
        $sys3 = "/lib/x86_64-linux-gnu" ascii
        $sys4 = "glibc" ascii

        // Development tools
        $dev1 = "clang" ascii
        $dev2 = "LLVM" ascii

    condition:
        // Jika punya banyak system indicators, kemungkinan bukan malware
        #sys1 + #sys2 + #sys3 + #sys4 + #dev1 + #dev2 < 3
}


rule Ransomware_Final_High_Confidence
{
    meta:
        description = "MALREV BY PYRG - Final high-confidence detection rule"
        author = "Security Analyst"
        date = "2024-12-31"
        severity = "critical"
        malware_family = "MALREV"
        attribution = "PYRG"
        reference = "Analyzed sample: 9011bac0f5a869e3484044cb18857ea5"

    strings:
        // TIER 1: MUST HAVE - Core ransomware behavior
        $tier1_aes_gcm = "EVP_aes_128_gcm" ascii
        $tier1_encrypt = "EVP_EncryptInit_ex" ascii
        $tier1_rand = "RAND_bytes" ascii
        $tier1_opendir = "opendir" ascii
        $tier1_readdir = "readdir" ascii

        // TIER 2: STRONG INDICATORS
        $tier2_malrev = ".malrev" ascii
        $tier2_mode_enc = "enc" ascii fullword
        $tier2_mode_dec = "dec-" ascii
        $tier2_fstatat = "fstatat" ascii

        // TIER 3: SUPPORTING EVIDENCE
        $tier3_unlink = "unlink" ascii
        $tier3_exit = "_exit" ascii
        $tier3_readlink = "readlink" ascii
        $tier3_proc_self = "/proc/self/exe" ascii
        $tier3_nice = { BF 0A 00 00 00 E8 }
        $tier3_docker = "docker" ascii
        $tier3_container = "containerd" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and

        // LOGIC: (TIER1 complete) AND (TIER2 indicators) [AND optionally TIER3]
        (
            // Scenario A: Extension .malrev + encryption
            (
                all of ($tier1_*) and
                $tier2_malrev
            )

            or

            // Scenario B: Mode selection + encryption + directory traversal
            (
                all of ($tier1_*) and
                ($tier2_mode_enc or $tier2_mode_dec) and
                $tier2_fstatat
            )

            or

            // Scenario C: Full encryption stack + suspicious behavior
            (
                all of ($tier1_*) and
                2 of ($tier2_*) and
                1 of ($tier3_*)
            )

            or

            // Scenario D: Self-delete behavior (STRONG indicator)
            (
                all of ($tier1_*) and
                $tier3_unlink and
                $tier3_exit and
                ($tier3_readlink or $tier3_proc_self)
            )
        )
}

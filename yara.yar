import "math"

rule Linux_Ransomware_AES_GCM_SelfDelete
{
    meta:
        description = "Deteksi ransomware Linux dengan AES-128-GCM dan self-delete"
        author = "Pacarnya Waguri"
        date = "2025-01-01"
        severity = "critical"
        malware_type = "Ransomware"
        target_os = "Linux"

    strings:
        // Encryption API calls
        $aes_gcm1 = "EVP_aes_128_gcm" ascii
        $aes_gcm2 = "EVP_EncryptInit_ex" ascii
        $aes_gcm3 = "EVP_EncryptUpdate" ascii
        $aes_gcm4 = "EVP_EncryptFinal_ex" ascii
        $aes_gcm5 = "EVP_CIPHER_CTX_ctrl" ascii
        $aes_gcm6 = "EVP_CIPHER_CTX_new" ascii

        // Decryption API calls
        $decrypt1 = "EVP_DecryptInit_ex" ascii
        $decrypt2 = "EVP_DecryptUpdate" ascii
        $decrypt3 = "EVP_DecryptFinal_ex" ascii

        // Random generation
        $rand = "RAND_bytes" ascii

        // File operations
        $unlink = "unlink" ascii
        $realpath = "realpath" ascii
        $readlink = "readlink" ascii

        // Directory traversal
        $opendir = "opendir" ascii
        $readdir = "readdir" ascii
        $fstatat = "fstatat" ascii

        // Command patterns
        $cmd_enc = "enc" ascii
        $cmd_dec = "dec-" ascii

        // Self-delete pattern (unlink argv[0])
        $self_delete = { 48 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? }

        // nice(10) - lower priority
        $nice_call = { BF 0A 00 00 00 E8 ?? ?? ?? ?? }

        // Anti-debug ptrace pattern
        $ptrace_check = { E8 ?? ?? ?? ?? 85 C0 74 ?? }

        // Memory cleanup pattern (memset 0)
        $mem_cleanup = { 31 C0 48 89 ?? B9 ?? ?? 00 00 F3 AA }

        // libc_start_main call
        $libc_start = "_libc_start_main" ascii

        // Typical buffer sizes for chunked encryption (256KB = 0x40000)
        $chunk_size = { 00 00 04 00 }

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            (
                4 of ($aes_gcm*) and
                $rand and
                2 of ($decrypt*) and
                $opendir and $readdir and
                $unlink and
                ($cmd_enc or $cmd_dec)
            )
            or
            (
                3 of ($aes_gcm*) and
                $rand and
                $self_delete and
                $ptrace_check and
                $nice_call
            )
            or
            (
                5 of them and
                $aes_gcm1 and
                $unlink and
                $opendir
            )
        )
}

rule Linux_Ransomware_Behavior_Pattern
{
    meta:
        description = "Deteksi pola behavior ransomware Linux"
        author = "Security Analyst"
        date = "2024-12-31"

    strings:
        // Kombinasi suspicious: encrypt + traverse + delete
        $combo1 = /EVP_(Encrypt|Decrypt)(Init|Update|Final)/ ascii
        $combo2 = /(opendir|readdir|scandir)/ ascii
        $combo3 = /(unlink|remove)/ ascii

        // Pattern: argc check untuk mode selection
        $argc_check = { 83 ?? 01 74 ?? 83 ?? 03 }

        // Pattern: string compare "enc" / "dec"
        $mode_check = { 80 38 65 75 ?? 80 78 01 6E }

        // Pattern: 16-byte key length check
        $key_len = { 83 F8 10 }

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            (all of ($combo*)) or
            ($combo1 and $combo2 and 2 of ($argc_check, $mode_check, $key_len))
        )
}

rule Linux_Ransomware_AntiDebug_Evasion
{
    meta:
        description = "Deteksi anti-debug dan evasion techniques"
        author = "Security Analyst"
        date = "2024-12-31"

    strings:
        // ptrace self-attach
        $ptrace = "ptrace" ascii

        // /proc/self/status check
        $proc_status = "/proc/self/status" ascii
        $tracer_pid = "TracerPid:" ascii

        // Process parent check
        $proc_stat = "/proc/self/stat" ascii
        $proc_cmdline = "/proc/%d/cmdline" ascii

        // Timing checks
        $gettimeofday = "gettimeofday" ascii
        $clock_gettime = "clock_gettime" ascii

        // VM detection strings
        $vmware = "VMware" ascii nocase
        $vbox = "VirtualBox" ascii nocase
        $qemu = "QEMU" ascii nocase

        // nice() for priority reduction
        $nice = { BF 0A 00 00 00 E8 ?? ?? ?? ?? }

        // readlink /proc/self/exe
        $readlink_self = "/proc/self/exe" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            3 of them or
            ($ptrace and $nice and $readlink_self)
        )
}

rule Linux_Ransomware_FileFormat_Encrypted
{
    meta:
        description = "Deteksi file yang sudah dienkripsi oleh ransomware ini"
        author = "Security Analyst"
        date = "2024-12-31"

    condition:
        filesize > 34 and
        math.entropy(18, filesize - 34) > 7.5 and
        math.entropy(filesize - 16, 16) > 7.0
}

rule Linux_Ransomware_Strings_Indicators
{
    meta:
        description = "Deteksi berdasarkan string indicators spesifik"
        author = "Security Analyst"
        date = "2024-12-31"

    strings:
        $s1 = "EVP_aes_128_gcm" ascii
        $s2 = "RAND_bytes" ascii
        $s3 = "EVP_CIPHER_CTX_ctrl" ascii
        $s4 = "opendir" ascii
        $s5 = "readdir" ascii
        $s6 = "fstatat" ascii
        $s7 = "unlink" ascii
        $s8 = "realpath" ascii
        $s9 = "nice" ascii
        $s10 = "_libc_start_main" ascii
        $s11 = "fopen" ascii
        $s12 = "fwrite" ascii
        $s13 = "fread" ascii

    condition:
        uint32(0) == 0x464c457f and
        8 of them
}

rule Linux_Ransomware_Crypto_Operations
{
    meta:
        description = "Deteksi operasi kriptografi AES-GCM"
        author = "Security Analyst"
        date = "2024-12-31"

    strings:
        $c1 = "EVP_EncryptInit_ex" ascii
        $c2 = "EVP_EncryptUpdate" ascii
        $c3 = "EVP_EncryptFinal_ex" ascii
        $c4 = "EVP_DecryptInit_ex" ascii
        $c5 = "EVP_DecryptUpdate" ascii
        $c6 = "EVP_DecryptFinal_ex" ascii
        $c7 = "EVP_aes_128_gcm" ascii
        $c8 = "EVP_CIPHER_CTX_new" ascii
        $c9 = "EVP_CIPHER_CTX_free" ascii
        $c10 = "RAND_bytes" ascii

    condition:
        uint32(0) == 0x464c457f and
        6 of them
}

rule Linux_Ransomware_Master_Detection
{
    meta:
        description = "Master rule - kombinasi semua indicators"
        author = "Security Analyst"
        date = "2024-12-31"
        severity = "critical"
        reference = "Analyzed sample"

    condition:
        Linux_Ransomware_AES_GCM_SelfDelete or
        Linux_Ransomware_Crypto_Operations or
        (
            Linux_Ransomware_Behavior_Pattern and
            Linux_Ransomware_Strings_Indicators
        ) or
        (
            Linux_Ransomware_AntiDebug_Evasion and
            Linux_Ransomware_Strings_Indicators
        )
}

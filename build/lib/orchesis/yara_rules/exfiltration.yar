rule ExfiltrationAttempt {
    meta:
        description = "Detects potential data exfiltration patterns"
        severity = "HIGH"
        category = "exfiltration"
        author = "Orchesis"
    strings:
        $url_pattern = /https?:\/\/[^\s]+\.(ru|cn|tk|xyz)\//
        $curl = "curl" nocase fullword ascii
        $wget = "wget" nocase fullword ascii
        $exfil_func = /requests\.(get|post)\s*\(/
        $base64_encode = "base64" nocase fullword ascii
        $suspicious_endpoint = /\/upload|\/exfil|\/collect|\/steal/i
    condition:
        filesize < 10MB and any of ($url_pattern, $suspicious_endpoint) and any of ($curl, $wget, $exfil_func) and $base64_encode
}

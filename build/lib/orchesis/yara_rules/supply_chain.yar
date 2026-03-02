rule SupplyChainIndicators {
    meta:
        description = "Detects suspicious supply-chain indicators"
        severity = "HIGH"
        category = "supply_chain"
        author = "Orchesis"
    strings:
        $latest = "@latest" nocase ascii
        $wildcard = "*" ascii
        $curl_pipe = /curl\s+[^|]+\|\s*(bash|sh)/ nocase
        $npm_preinstall = "preinstall" nocase fullword ascii
    condition:
        filesize < 5MB and (any of ($curl_pipe, $npm_preinstall) or all of ($latest, $wildcard))
}

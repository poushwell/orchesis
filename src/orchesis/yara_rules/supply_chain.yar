rule SupplyChainIndicators {
    meta:
        description = "Detects suspicious supply-chain indicators"
        severity = "HIGH"
        category = "supply_chain"
        author = "Orchesis"
    strings:
        $latest = "@latest" nocase
        $wildcard = "*" 
        $curl_pipe = /curl\s+[^|]+\|\s*(bash|sh)/ nocase
        $npm_preinstall = "preinstall" nocase
    condition:
        any of ($curl_pipe, $npm_preinstall) or all of ($latest, $wildcard)
}

rule PromptInjection {
    meta:
        description = "Detects prompt injection patterns in skill files"
        severity = "CRITICAL"
        category = "injection"
        author = "Orchesis"
    strings:
        $ignore_prev = "ignore previous instructions" nocase ascii
        $ignore_above = "ignore all above" nocase ascii
        $system_prompt = "system prompt" nocase ascii
        $act_as = /act as (a |an )?(admin|root|system)/ nocase
        $jailbreak = "DAN" fullword ascii
    condition:
        filesize < 1MB and any of them
}

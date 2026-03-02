rule PromptInjection {
    meta:
        description = "Detects prompt injection patterns in skill files"
        severity = "CRITICAL"
        category = "injection"
        author = "Orchesis"
    strings:
        $ignore_prev = "ignore previous instructions" nocase
        $ignore_above = "ignore all above" nocase
        $system_prompt = "system prompt" nocase
        $act_as = /act as (a |an )?(admin|root|system)/ nocase
        $jailbreak = "DAN"
    condition:
        any of them
}

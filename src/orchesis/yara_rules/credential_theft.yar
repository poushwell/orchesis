rule CredentialHarvesting {
    meta:
        description = "Detects likely credential theft behavior"
        severity = "CRITICAL"
        category = "credential_theft"
        author = "Orchesis"
    strings:
        $aws_creds = ".aws/credentials" nocase
        $ssh_key = ".ssh/id_rsa" nocase
        $env_file = ".env" nocase
        $post = /requests\.post\s*\(/
        $webhook = "webhook.site" nocase
    condition:
        any of ($aws_creds, $ssh_key, $env_file) and any of ($post, $webhook)
}

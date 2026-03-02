rule CredentialHarvesting {
    meta:
        description = "Detects likely credential theft behavior"
        severity = "CRITICAL"
        category = "credential_theft"
        author = "Orchesis"
    strings:
        $aws_creds = ".aws/credentials" nocase ascii
        $ssh_key = ".ssh/id_rsa" nocase ascii
        $env_file = ".env" nocase ascii
        $post = /requests\.post\s*\(/
        $webhook = "webhook.site" nocase ascii
    condition:
        filesize < 10MB and any of ($aws_creds, $ssh_key, $env_file) and any of ($post, $webhook)
}

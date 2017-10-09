$data = @{
    host_config_key='<Key>'
    extra_vars='{"role_name": "role"}' | ConvertFrom-Json
} | ConvertTo-Json

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Method Post -Uri https://<server>/api/v2/job_templates/01/callback/ -Body $data -ContentType application/json -UseBasicParsing

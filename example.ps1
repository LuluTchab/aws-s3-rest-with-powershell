using module .\ScalityAPI.psm1

# Fill with appropriate values
$server = "s3-host.domain"
$accessKey = "will with access key"
$secretKey = "fill with secret key"
$region = "us-east-1"

$scalityApi = [ScalityAPI]::new($server, $accessKey, $secretKey, $region)

$list = $scalityApi.getBucketList()

Write-Host (Convertto-JSON $list)
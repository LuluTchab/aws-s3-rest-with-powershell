<#
   This code shows how to do a REST API request on S3 using PowerShell.

        Documentation API REST : 
        S3: https://docs.aws.amazon.com/AmazonS3/latest/API/Type_API_Reference.html
        
        All authentication documentation can be found here:
        https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
        More especially
        https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
#>

$global:XAAS_S3_ALGORITHM = 'AWS4-HMAC-SHA256'
$global:XAAS_S3_CONTENT_TYPE = 'application/x-amz-json-1.0'

class ScalityAPI
{

    hidden [string] $_secretKey
    hidden [string] $_accessKey
    hidden [string] $_server
    hidden [string]$_baseUrl
    hidden [HashTable] $_headers
    hidden [string] $_region

    <#
	-------------------------------------------------------------------------------------
        BUT : Class constructor
        
        IN  : $server       -> S3 server FQDN
        IN  : $accessKey    -> Access Key
        IN  : $secretKey    -> Secret Key
        IN  : $region       -> S3 Region
	#>
	ScalityAPI([string]$server, [string]$accessKey, [string]$secretKey, [string]$region)
	{
        $this._headers = @{}
		$this._baseUrl = "https://{0}" -f $server
		$this._server = $server
        
        $this._secretKey = $secretKey
        $this._accessKey = $accessKey
        $this._region = $region
    }


    <#
	-------------------------------------------------------------------------------------
        GOAL : Converts XML ([xml] type) into an object that can easily be used with PowerSheill

        IN  : $xml      -> XML to convert
        
        RET : Object 

        REMARK: Code inspired and adapted from folloging solution:: https://stackoverflow.com/questions/42636510/convert-multiple-xmls-to-json-list
    #>
    [PSCustomObject] _convertXMLToObject([System.Xml.XmlNode]$xml)
    {
        # If node only contains data (text)
        if ($xml.FirstChild -is [system.xml.xmltext]) 
        {
            return $xml.FirstChild.InnerText
        }
        else # Node is a object (with children)
        {
            # Removing all child nodes that have information about schema
            if($null -ne ($xmlSchema = $xml.ChildNodes | Where-Object { $_ -is [System.XML.XmlDeclaration] }))
            {
                $xml.removeChild($xmlschema) | Out-Null
            }

            $xmlPropList = @($xml | get-member -MemberType property | Select-Object -ExpandProperty Name)
            <# This allows to detect arrays of identical nodes (with same name). The case in which we also have "others" nodes with different names added
            to the ones with the same name is handled below #>
            if(($xmlPropList.count -eq 1) -and ($xml.ChildNodes.count -gt 1))
            {
                $array = @()
                foreach ($child in $xml.ChildNodes) 
                {
                    $array += ($this._convertXMLToObject($child))
                }
                return $array
            }
            else
            {
                $obj = [ordered]@{}
                foreach($child in $xml.ChildNodes) 
                {
                    <# In some cases, we can have a child node with called 'Name', which override the native 'Name' property of a XML node, meaning that we cannot
                        retrieve it. To retrieve it (and it could be a bit dirty but it works), we'll:
                        - remove all child nodes
                        - retrieve node 'Name' property 
                        - add child nodes again
                    #>
                    $extractedSubChildList = @()
                    while($child.childnodes.count -gt 0)
                    {
                        $extractedSubChildList += $child.removeChild($child.FirstChild)
                    }
                    # Retrieving node property
                    $propName = $child.name
                    
                    foreach($extractedSubChild in $extractedSubChildList)
                    {
                        $child.AppendChild($extractedSubChild) | Out-Null
                    }

                    <# If we have several nodes with actual name, it means it's an array.
                        Thus, we'll count only the nodes that have actual name as 'Name' and ignore the other nodes 
                        (because sometimes we can have several nodes with same names PLUS others nodes with completely different names)#>
                    if(($xml.childnodes | WHere-Object { $_.name -eq $propName }).count -gt 1)
                    {
                        if($null -eq $obj.$propName)
                        {
                            $obj.Add($propName, @())
                        }
                        $obj.$propName += $this._convertXMLToObject($child)
                    }
                    else # We have only one element (not an array)
                    {
                        $obj.Add($propName, $this._convertXMLToObject($child))
                    }
                    
                }
                return $obj
            }
        }
    }


    <#
    -------------------------------------------------------------------------------------
        GOAL: Returns specified hash of a given string

        IN  : $string	-> String to get hash from
        IN  : $hashName	-> Name of hash function to use
                            - MD5
                            - SHA1
                            - SHA256
                            - SHA384
                            - SHA512

        RET : String hash
    #>
    hidden [string] _getStringHash([String]$string, [string]$hashName)
    { 
        $stringBuilder = New-Object System.Text.StringBuilder 
        [System.Security.Cryptography.HashAlgorithm]::Create($hashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($string))| ForEach-Object{ 
            [Void]$stringBuilder.Append($_.ToString("x2")) 
        } 
        return $stringBuilder.ToString() 
    }


    <#
	-------------------------------------------------------------------------------------
        GOAL: Signs a message with a given key
        
        IN  : $key              -> key to use
        IN  : $message          -> Message to sign

        RET : Array with object, containing signed message
	#>
    hidden [Object[]] _getSignedMessage([Byte[]]$key, [string]$message)
    {
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = $key
        return $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
    }


    <#
	-------------------------------------------------------------------------------------
        GOAL: Returns signature key for an API request
        
        IN  : $dateStamp        -> Request date
        IN  : $serviceName      -> Name of the service for which we want to do the request
                                    Ex: s3

        RET : Array with object, containing signature key
	#>
    hidden [Object[]] _getSigninKey([string]$dateStamp, [string]$serviceName)
    {
        $kDate = $this._getSignedMessage([Text.Encoding]::ASCII.GetBytes(('AWS4{0}' -f $this._secretKey)), $dateStamp)
        $kRegion = $this._getSignedMessage($kDate, $this.region)
        $kService = $this._getSignedMessage($kRegion, $serviceName)        
        return $this._getSignedMessage($kService, 'aws4_request')
    }


    <#
		-------------------------------------------------------------------------------------
		GOAL: Call the S3 REST API

        IN  : $service      -> Service to contact (EX: s3)
		IN  : $uri		    -> URL to call, has to be relative
		IN  : $method	    -> Method to use (Post, Get, Put, Delete)
		IN  : $xmlBody      -> XML Object to pass as body
						 	    (can be $null)

		RET : Returns call result.
                It looks like that, by default, there is always a 'root' XML node in which we can found the
                returned result. Thus, if so, we'll return directly the content of the unique node.
	#>
    hidden [PSCustomObject] _callAPI([string]$service, [string]$uri, [string]$method, [XML]$xmlBody)
    {

        $this._headers = @{}

		$uri = "{0}{1}" -f $this._baseUrl, $uri

        # Add information about region
        if(([System.Uri]$uri).query.StartsWith("?"))
        {
            $uri = "{0}&bucket-region={1}" -f $uri, $this.region
        }
        else
        {
            $uri = "{0}?bucket-region={1}" -f $uri, $this.region
        }

        # Creating body
        if($null -eq $xmlBody)
        {
            $this._headers.add('Content-Type', $global:XAAS_S3_CONTENT_TYPE)
            $bodyXML = ""
        }
        else
        {
            $this._headers.add('Content-Type', 'text/plain')
            $bodyXML = $xmlBody.OuterXml
        }

        $bodyHASH = ($this._getStringHash($bodyXML, "SHA256"))

        # Getting UTC timestamp for request
        $now = (Get-Date).ToUniversalTime()
        $amzDate = Get-Date $now -Format "yyyyMMddTHHmmssZ"
        $dateStamp = Get-Date $now -Format "yyyyMMdd"

        # Adding some headers
        $this._headers.add('X-Amz-Content-Sha256', $bodyHASH)
        $this._headers.add('X-Amz-Date', $amzDate)

        $allCanonicalHeader = $this._headers.clone()
        $allCanonicalHeader.host = $this._server

        # Generate header list, sorted by name (lowercase) with their values (because it's that format that is expected by AWS)
        $canonicalHeaders = ($allCanonicalHeader.keys | sort-object | ForEach-Object { "{0}:{1}`n" -f $_.toLower(), $allCanonicalHeader.$_ } ) -join ""
        
        # Header name list, separated with ";"
        $signedHeaders = ($allCanonicalHeader.keys | sort-object | ForEach-Object {$_.toLower() }) -join ";"
        
        $sortedQueryPartList = @()
        <# According to documentation, we have to sort parameters in query string, so we'll do that here. And we'll also remove the "?" at the
        beginning.
        Finally, we also add "=" to parameters with no value #>
        ForEach($queryPart in @((([System.Uri]$uri).query -replace "^\?","").split("&") | Sort-Object))
        {
            if($queryPart -notMatch "^(.*?)=")
            {
                $queryPart = "{0}=" -f $queryPart
            }
            $sortedQueryPartList += $queryPart
        }
        $sortedQuery = $sortedQueryPartList -join "&"
        $canonicalRequest = "{0}`n{1}`n{2}`n{3}`n{4}`n{5}" -f $method, ([System.Uri]$uri).AbsolutePath, $sortedQuery, $canonicalHeaders, $signedHeaders, $bodyHASH
        
        $credentialScope = '{0}/{1}/{2}/aws4_request'  -f $dateStamp, $this.region, $service

        $stringToSign = "{0}`n{1}`n{2}`n{3}" -f $global:XAAS_S3_ALGORITHM, $amzDate, $credentialScope, ($this._getStringHash($canonicalRequest, "SHA256"))

        $signingKey = $this._getSigninKey($dateStamp, $service)

        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = $signingKey
        $signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($stringToSign))
        # To have the same format as the one expected by AWS, we have to apply following solution
        # https://stackoverflow.com/questions/53529347/hmac-sha256-powershell-convert
        $signature = [System.BitConverter]::ToString($signature).Replace('-','').ToLower()

        $authorizationHeader = '{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}' -f $global:XAAS_S3_ALGORITHM, $this._accessKey, $credentialScope, $signedHeaders, $signature

        $this._headers.add('Authorization', $authorizationHeader)

        # REST call
        $xmlResponse = Invoke-RestMethod -Uri $uri -Method $method -Body $bodyXML -Headers $this._headers -SkipCertificateCheck -SkipHeaderValidation
        
        $response = $this._convertXMLToObject($xmlResponse)

        # Error handling
        if($null -ne $response.error)
        {
            Throw ("{0}`n{1}" -f $response.error.code, $response.error.message)
        }

        # if no key in the object, it can be considered as $null (nothing returned by API call)
        if($response.keys.count -eq 0)
        {
            return $null
        }
        # Checking if only one key in result (as mentionned in function header)
        if($response.keys.count -eq 1)
        {
            $response = $response.($response.keys[0])
            # Again, if no key in the object, it can be considered as $null
            if($response.keys.count -eq 0)
            {
                return $null
            }
            
        }
        
        return $response
    }


    <#
	-------------------------------------------------------------------------------------
        GOAL: Do some REST requests to retrieve content of a list. Thus, we'll have to handle paging.

        IN  : $service                  -> Service to contact (ex: s3)
        IN  : $uri                      -> URL (relative)
        IN  : $resultPropertyName       -> Name of the property in which we have to go to look for result list
        IN  : $pagingQueryParam         -> Name of query parameter to use to do paging
        IN  : $pagingResultPropertyName -> Name of the result property in which we can find the information about paging (if any)                                        
        
        RET : Array with expected element list
	#>
    hidden [Array] _getObjectList([string]$service, [string]$uri, [string]$resultPropertyName, [string]$pagingQueryParam, [string]$pagingResultPropertyName)
    {
        $tmpUri = $uri

        $result = $null
        $list = @()
        do
        {
            if($null -ne $result)
            {
                if($tmpUri -like "*?*")
                {
                    $tmpUri = "{0}&{1}={2}" -f $uri, $pagingQueryParam, $result.$pagingResultPropertyName
                }
                else
                {
                    $tmpUri = "{0}?{1}={2}" -f $uri, $pagingQueryParam, $result.$pagingResultPropertyName    
                }
                
            }
            $result = $this._callAPI($service, $tmpUri, "GET", $null)
            
            if($null -ne $result.$resultPropertyName)
            {
                $list += $result.$resultPropertyName
            }
            
        }
        while($null -ne $result.$pagingResultPropertyName)
        
        return $list
    }


    <#
	-------------------------------------------------------------------------------------
        GOAL: Returns bucket list

        RET : Bucket list

        https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
	#>
    [Array] getBucketList()
    {
        return $this._getObjectList("s3", "/", "Buckets", "continuation-token", "ContinuationToken")
    }


    <#
	-------------------------------------------------------------------------------------
        BUT : Returns Bucket object list
        
        IN  : $bucketName   -> Bucket name

        RET : Array with objects information

        https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
	#>
    [PSCustomObject] getBucketObjectList([string]$bucketName)
    {
        $uri = "/{0}/?list-type=2" -f $bucketName

        return $this._getObjectList("s3", $uri, "Contents", "continuation-token", "NextContinuationToken")
    }

}
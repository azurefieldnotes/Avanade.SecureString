<#
    .SYNOPSIS
        Encrypts a SecureString with the specified encryption key
    .PARAMETER StringToEncrypt
        The string to be encrypted
    .PARAMETER SecureStringToEncrypt
        The string to be encrypted
    .PARAMETER EncryptionKey
        The encryption key
#>
Function New-EncryptedString
{
    [OutputType([String])]
    [CmdletBinding(DefaultParameterSetName='plain')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='plain',Position=0,ValueFromPipeline=$true)]
        [String[]]
        $StringToEncrypt,
        [Parameter(Mandatory=$true,ParameterSetName='secure',Position=0,ValueFromPipeline=$true)]
        [securestring[]]
        $SecureStringToEncrypt,
        [Parameter(Mandatory=$true,ParameterSetName='secure',Position=1)]
        [Parameter(Mandatory=$true,ParameterSetName='plain',Position=1)]
        [ValidateLength(16,32)]
        [String]
        $EncryptionKey
    )
    BEGIN
    {
        $EncryptionKeyBytes=[System.Text.Encoding]::ASCII.GetBytes($EncryptionKey)
    }
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'plain')
        {
            foreach ($item in $StringToEncrypt)
            {
                $SecureString=ConvertTo-SecureString -String $item -AsPlainText -Force
                $Encrypted = ConvertFrom-SecureString -SecureString $SecureString -Key $EncryptionKeyBytes
                Write-Output $Encrypted
            }
        }
        else
        {
            foreach ($SecureString in $SecureStringToEncrypt)
            {
                $Encrypted = ConvertFrom-SecureString -SecureString $SecureString -Key $EncryptionKeyBytes
                Write-Output $Encrypted
            }
        }
    }
}

<#
    .SYNOPSIS
        Decrypts a SecureString that was encrypted with the specified key
    .PARAMETER StringToDecrypt
        The encrypted SecureString
    .PARAMETER EncryptionKey
        The encryption key
    .PARAMETER AsPlainText
        Returns the value as a plain string
#>
Function Get-EncryptedString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [String[]]
        $StringToDecrypt,
        [Parameter(Mandatory=$true)]
        [ValidateLength(16,32)]
        [String]
        $EncryptionKey,
        [Parameter(Mandatory=$false)]
        [Switch]
        $AsPlainText
    )
    BEGIN
    {
        $EncryptionKeyBytes=[System.Text.Encoding]::ASCII.GetBytes($EncryptionKey)
    }
    PROCESS
    {
        foreach ($item in $StringToDecrypt)
        {
            $Decrypted = ConvertTo-SecureString -String $item -Key $EncryptionKeyBytes
            if($AsPlainText.IsPresent)
            {
                $Decrypted=(New-Object PSCredential("anyuser",$Decrypted)).GetNetworkCredential().Password
            }
            Write-Output $Decrypted
        }
    }
}

<#
    .SYNOPSIS
        Generates a new encryption key for use with a SecureString
    .PARAMETER KeyLength
        The length of the key in bits 128,196, or 256
#>
Function New-EncryptedStringKey
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [ValidateSet(128,196,256)]
        [Parameter(Mandatory=$false)]
        [int]
        $KeyLength=128,
        [Parameter(Mandatory=$false)]
        [Switch]
        $UseRandomNumberGenerator
    )
    $CharCount=$KeyLength/8
    $ClientSecret=New-Object System.String($CharCount)
    $Seed = New-Object System.Byte[]($CharCount)
    $NumGen = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    if($UseRandomNumberGenerator.IsPresent)
    {
        try
        {
            $NumGen.GetBytes($Seed)
            $ClientSecret = [System.Convert]::ToBase64String($Seed)
        }
        finally
        {
            if($NumGen -ne $null)
            {
                $NumGen.Dispose()
            }
        }
    }
    else
    {
        $AvailChars=("1,2,3,4,5,6,7,8,9,0," + `
            "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z," + `
            "-,+,=,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z," +
            "!,@,#,$,%,^,&,*,<,>,?,/,|,\").Split(',')
        $CharCount=$KeyLength/8
        $EndChars=Get-Random -InputObject $AvailChars -Count $CharCount
        $ClientSecret=([String]::Join([String]::Empty,$EndChars))
    }
    return $ClientSecret
}
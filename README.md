[@azurefieldnotes]: https://twitter.com/azurefieldnotes

# Avanade.SecureString

Simple String Encryption/Decryption methods

### Exposed Cmdlets

* New-EncryptedStringKey
    * Generates a new encryption key for use with a SecureString
* New-EncryptedString
    * Encrypts a SecureString with the specified encryption key
* Get-EncryptedString
    * Decrypts a SecureString that was encrypted with the specified key

### Usage

    $key=New-EncryptedStringKey -KeyLength 128
    $encString=New-EncryptedString -StringToEncrypt "MaybeAPassword" -EncryptionKey $key
    $decString=Get-EncryptedString -StringToDecrypt $encString -EncryptionKey $key
or

    $decString=Get-EncryptedString -StringToDecrypt $encString -EncryptionKey $key -AsPlainText

## Follow us on Twitter [@azurefieldnotes][]

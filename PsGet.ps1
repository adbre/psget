#
# Copyright (C) 2013 Adam Brengesjö <ca.brengesjo@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# http://github.com/adbre/psget
#
param(
    [string]$InputFile = "psget.config",
    [string]$DownloadDirectory = [System.IO.Path]::Combine(${env:LOCALAPPDATA}, "PsGet\Cache"),
    [string]$Output = "packages",
    [string]$Username = [Environment]::UserName,
    [string]$Password,
    [bool]$UnpackInSubdirectory = $true,
    [bool]$Interactive = $true,
    [string]$Curl,
    [string]$7Zip,
    [string]$unzip
)

function main
{
    DownloadAndUnpackFiles `
        -fileEntries (ReadInputFile -fileName $(GetRootedPath $InputFile)) `
        -downloadDirectory (GetRootedPath $DownloadDirectory) `
        -unpackDirectory (GetRootedPath $Output) `
        -username $Username `
        -password $Pasword
}

function NewInputFileEntry
{
    $entry = new-object psobject
    Add-Member -InputObject $entry -MemberType NoteProperty -Name Url -Value $null
    Add-Member -InputObject $entry -MemberType NoteProperty -Name Md5Checksum -Value $null
    Add-Member -InputObject $entry -MemberType NoteProperty -Name DownloadFileName -Value $null
    Add-Member -InputObject $entry -MemberType NoteProperty -Name UnpackDestination -Value $null

    return $entry
}

function ReadInputFile
{
param(
    [string]$fileName,
    [string]$downloadDirectory,
    [string]$unpackDirectory
)

    $currentLine = 1
    $fileEntries = @()
    Get-Content $fileName | foreach {
        if (![String]::IsNullOrWhitespace($_))
        {        
            $words = $_.Split(' ')
            if (($words.Count -ne 1) -and ($words.Count -ne 2)) {
                throw "Expected a single or two words (separated by a space) on each line. But I got $($words.Count) words on line $currentLine Make sure you trim any excess whitespaces."
            }
        
            $entry = NewInputFileEntry
            $entry.Url = $words[0]

            if ($words.Count -gt 1) {
                $entry.Md5Checksum = $words[1]
            }

            $uri = $null
            if (![Uri]::TryCreate($entry.Url, [UriKind]::Absolute, [ref]$uri)) {
                throw "First word on line $currentLine is not a valid URI"
            }

            if (($uri.Scheme -ne "http") -and ($uri.Scheme -ne "https")) {
                throw "$($uri.Scheme) is not a supported scheme. On line $currentLine"
            }

            if ((![String]::IsNullOrWhitespace($entry.Md5Checksum)) -and (!(IsMd5Checksum $entry.Md5Checksum))) {
                throw "If the second word is specified, it must be a valid MD5 checksum ([0-9a-fA-F]{32}). On line $currentLine"
            }

            $fileEntries += $entry
        }

        $currentLine += 1
    }

    return $fileEntries
}

function DownloadFile
{
param(
    [string]$url,
    [string]$fileName,
    [string]$username,
    [string]$password
)
    # A note to the maintainer:
    #
    # I'd prefer to use System.Net.WebClient instead of curl, to remove the dependency on curl.
    # But after having spent hours(!) trying to get the digest credentials configuration to work properly, I resorted to using curl
    # (which I knew to be working).
    #
    # Have tried the following documentation, without any luck
    #
    #   http://stackoverflow.com/questions/3172510/how-can-i-do-digest-authentication-with-httpwebrequest
    #   http://stackoverflow.com/questions/1970465/https-digest-authentication
    #   http://msdn.microsoft.com/en-us/library/system.net.credentialcache.aspx
    #   ... and many more
    #

    $curl = GetDefaultOrFindFullPath "Git\bin\curl.exe" $Curl
    if (![System.IO.File]::Exists($curl)) {
        Write-Error "This script requires Curl which is shipped with the Git for Windows installation (http://git-scm.org)"
        throw "File does not exists: $curl"
    }

    CreateParentDirectoryIfNotExists $fileName

    Write-Host "D $url"
    if ((![String]::IsNullOrWhitespace($username)) -and (![String]::IsNullOrWhitespace($password))) {
        $credentials = [string]::Format("{0}:{1}", $username, $password)            
        & $curl --fail -o "$fileName" --progress-bar --location --digest -u "$credentials" "$url" >$null
    } else {
        & $curl --fail -o "$fileName" --progress-bar --location "$url" >$null
    }

    # Hack. We don't want the caller to be aware we are using curl.
    # But we must let the caller know why we failed (so that TryDownloadFile may ask the user for credentials...)
    # Return the HTTP status code for access denied if curl returns 22.
    if ($LastExitCode -eq 22) {
        return 401
    } else {
        return $LastExitCode
    }
}

function TryDownloadFileOrAskForCredentials
{
param(
    [string]$url,
    [string]$fileName,
    [string]$username,
    [string]$password
)
    for ($i = 0; $i -le 5; $i++)
    {
        if ([string]::IsNullOrWhitespace($password)) {
            $credentials = GetCredentialsFromCache $url
            if ($credentials) {
                $username = $credentials.UserName
                $password = $credentials.Password
            }
        }

        $exitCode = DownloadFile $url $fileName $username $password

        if ($exitCode -eq 401) {
            $credentials = GetCredentialsFromCache $url
            if (!$credentials -and $Interactive) {
                Write-Host
                Write-Host "Access denied. Enter username and password to continue."
                $credentials = AskForCredentials $username
            } elseif (!$credentials -and !$Interactive) {
                break
            }

            $username = $credentials.UserName
            $password = $credentials.Password
            continue
        } elseif ($exitCode -eq 0) {
            if ($credentials) {
                SaveCredentialsInCache $url $credentials
            }
            return
        }
    }

    throw "Download failed."
}

$CredentialCache = New-Object System.Net.CredentialCache

function GetCredentialsFromCache($url)
{
    $uri = new-object Uri $url
    return $CredentialCache.GetCredential($uri, "Gummibear")
}

function SaveCredentialsInCache($url, $credentials)
{
    $uri = new-object Uri $url
    $prefix = new-object UriBuilder
    $prefix.Scheme = $uri.Scheme
    $prefix.Host = $uri.Host
    $prefix.Port = $uri.Port

    $CredentialCache.Remove($prefix.Uri, "Gummibear")
    $CredentialCache.Add($prefix.Uri, "Gummibear", $credentials)
}

function AskForCredentials ($defaultUsername) {
    if ([string]::IsNullOrWhitespace($defaultUsername)) {
        do {
            $username = Read-Host "Username"
        } while ([string]::IsNullOrWhitespace($username))
    } else {
        $username = Read-Host "Username [$defaultUsername]"
        if ([string]::IsNullOrWhitespace($username)) {
            $username = $defaultUsername
        }
    }
    
    do {
        $password = Read-Host "Password" -AsSecureString
    } while ($password.Length -eq 0)

    return new-object -type system.net.networkcredential $username,$password
}

function CreateDirectoryIfNotExists($path) {
    if (![System.IO.Directory]::Exists($path)) {
        $v = [System.IO.Directory]::CreateDirectory($path)
    }
}

function DeleteDirectoryIfExists($path) {
    if ([System.IO.Directory]::Exists($path)) {
        Remove-Item $path -Recurse -Force
    }
}

function CreateParentDirectoryIfNotExists($fileName) {
    CreateDirectoryIfNotExists ([System.IO.Path]::GetDirectoryName($fileName))
}

function GetRootedPath($path) {
    $here = (Get-Location) 
    if (![System.IO.Path]::IsPathRooted($path)) {
        $path = [System.IO.Path]::Combine($here, $path)
                
    }
    
    return $path
}

function TryDownloadAndVerifyFile
{
param(
    [string]$url,    
    [string]$fileName,
    [string]$expectedMd5Checksum,
    [string]$username,
    [string]$password
)    
    if (([System.IO.File]::Exists($fileName)) -and (Md5ChecksumMatches $fileName $expectedMd5Checksum)) {
        return
    }

    TryDownloadFileOrAskForCredentials $url $fileName $username $password

    # Terminate if we expected a md5 checksum but validation failed
    if ((![string]::IsNullOrWhitespace($expectedMd5Checksum)) -and !(Md5ChecksumMatches $fileName $expectedMd5Checksum)) {
        throw "Downloaded file $fileName does not match expected checksum $expectedMd5Checksum"
    }
}

function Md5ChecksumMatches($fileName, $expectedMd5Checksum)
{
    if (![System.IO.File]::Exists($fileName) -or !(IsMd5Checksum($expectedMd5Checksum))) {
        return $false
    }

    $actualMd5Checksum = ComputeMd5Checksum $fileName
    return [string]::Equals($expectedMd5Checksum, $actualMd5Checksum, [StringComparison]::OrdinalIgnoreCase)
}

function ComputeMd5Checksum($fileName)
{
    try {
        $md5 = [System.Security.Cryptography.Md5]::Create()
        $stream = [System.IO.File]::OpenRead($fileName)
        $bytes = $md5.ComputeHash($stream)
        return ConvertByteArrayToHexString($bytes)
    } finally {
        if ($md5 -ne $null) {
            $md5.Dispose()
        }
        if ($stream -ne $null) {
            $stream.Dispose()
        }
    }
}

function ConvertByteArrayToHexString($bytes)
{
    $result = ""
    foreach ($byte in $bytes) {
        $result += $byte.ToString("x2")
    }
    return $result
}

function IsMd5Checksum($s) {
    return ($s -match '[0-9a-fA-F]{32}')
}

function DownloadAndUnpackFile
{
param(
    [string]$url,
    [string]$username,
    [string]$password,
    [string]$expectedMd5Checksum,
    [string]$downloadDirectory,
    [string]$unpackDirectory
)

    $fileName = [System.IO.Path]::GetFileName($url)
    $downloadOutput = [System.IO.Path]::Combine($downloadDirectory, $fileName)

    TryDownloadAndVerifyFile `
        -url $url `
        -username $username `
        -password $password `
        -fileName $downloadOutput `
        -expectedMd5Checksum $expectedMd5Checksum
    
    UnpackFile `
        -archive $downloadOutput `
        -output $unpackDirectory
}

function UnpackFile
{
param(
    [string]$archive,
    [string]$output
)

    if ($UnpackInSubdirectory) {
        $fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($archive)
        $output = [System.IO.Path]::Combine($output, $fileNameWithoutExtension)
    }

    Write-Host "U $archive -> $output"

    DeleteDirectoryIfExists $output
    CreateDirectoryIfNotExists $output

    $7z = GetDefaultOrFindFullPath -path "7-Zip\7z.exe" -default $7Zip
    $unzipExe = GetDefaultOrFindFullPath -path "Git\bin\unzip.exe" -default $unzip

    if ($7z -and [System.IO.File]::Exists($7z)) {
        UnpackFileWith7Zip $7z $archive $output
    } elseif ($unzipExe -and [System.IO.File]::Exists($unzipExe)) {
        UnpackFileWithUnzip $unzipExe $archive $output
    } else {
        Write-Host "To enable unpacking, either 7-Zip <http://www.7-zip.org/download.html> or Git for windows (http://git-scm.org) must be installed"
        Write-Host "You can also specify the path to 7-Zip with the -7Zip parameter,"
        Write-Host "Or the path to unzip with -unzip parameter."
        throw "Cannot find neither 7zip or unzip"
    }
}

function UnpackFileWith7Zip
{
param(
    [string]$7z,
    [string]$archive,
    [string]$output
)
    & $7z e -y "-o$output" $archive >$null
    if ($LastExitCode -ne 0) {
        throw "unzip returned with exit code $LastExitCode"
    }
}

function UnpackFileWithUnzip
{
param(
    [string]$unzip,
    [string]$archive,
    [string]$output
)

    & $unzip -o $archive -d $output >$null
    if ($LastExitCode -ne 0) {
        throw "7zip returned with exit code $LastExitCode"
    }
}

function DownloadAndUnpackFiles
{
param(
    $fileEntries,
    [string]$downloadDirectory,
    [string]$unpackDirectory,
    [string]$username,
    [string]$password
)

    foreach ($entry in $fileEntries) {
        DownloadAndUnpackFile `
            -url $entry.Url `
            -username $username `
            -password $password `
            -expectedMd5Checksum $entry.Md5Checksum `
            -downloadDirectory $downloadDirectory `
            -unpackDirectory $unpackDirectory
    }
}

function GetDefaultOrFindFullPath($path, $default) {
    if (![string]::IsNullOrWhitespace($default) -and [System.IO.File]::Exists($default)) {
        return $default
    } else {
        return FindFullPath $path
    }
}

function FindFullPath($path) {
    $prefixes = (${env:ProgramFiles(x86)},${env:ProgramFiles})
    foreach ($prefix in $prefixes) {
        $currentPath = [System.IO.Path]::Combine($prefix, $path)
        if ([System.IO.File]::Exists($currentPath)) {
            return $currentPath
        }
    }

    return $null
}

main

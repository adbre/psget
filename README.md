psget
=====

I developed this tool because I wanted to automate downloading of packages from the BitBucket
downloads section, to be used by CI tools.

It requires a configuration file which is basically a text file of URLs and MD5 hashes, separated
by a space. If the downloaded file doesn't match with the configured MD5 hash, execution will be
aborted.

The purpose of this validation is to break the build if someone has modified the file on the remote
host.

When a file is downloaded it's written to a cache in %LOCALAPPDATA%\PsGet\Cache so that the file
doesn't have to be downloaded more than once. If the file in the cache mismatches with the
configured MD5 checksum however, the file will be downloaded again, overwriting the existing file
in the cache.

If the a line in the input file only contains a URL, the file will always be downloaded, providing
a mechanisim of forcing getting the latest version.


#### Example psget.config

    http://middle.of/nowhere/download.if.not.in.cache.zip a1b2c3d4e5f6a7b8c9d1e2f3a4b5c6
    http://middle.of/nowhere/always.download.zip

#### Example invocation #1

    .\PsGet.ps1

#### Example invocation #2
This example demonstrates how the script could be called in a build environment, and using a custom configuration filename and output directory.

    .\PsGet.ps1 -Username $env:psgetUsername -Password $env:psgetPassword -Output ext -InputFile references.cfg


#### Caching username and password
By setting the -SaveCredentials switch, PsGet.ps1 will immediatly prompt you for a username and password, and saving it to your local profile
so you don't have to be prompted for a password everytime PsGet.ps1 invokes.

    .\PsGet.ps1 -SaveCredentials

## Requirements

PsGet.ps1 depends on curl.exe from the Git for Windows installation to do the heavy lifting.

And for unpacking PsGet.ps1 uses 7-Zip do unpack the downloaded archives. As a fallback, PsGet.ps1 uses
unzip.exe from the Git for Windows distribution.


## Commandline options

##### -InputFile *file*
If set, uses this file as input instead of ".\psget.config"

##### -DownloadDirectory *path*
Sets the path where downloaded files will be stored. Defaults to %LOCALAPPDATA%\PsGet\Cache

##### -Output *path*
Sets the path to where packages (zip files) will be unpacked. Defaults to ".\packages"

##### -Username *username*
Sets the username to use when authenticating with the remote HTTP server. Defaults to the current user.
If omitted, and the server responds with 401 access denied, the user will be prompted for other credentials.

##### -Password *password*
Sets the password to use in HTTP authentication along with -Username. If omitted, user will be prompted for a password.

##### -UnpackInSubdirectory *true/false*
Sets a boolean value wether the downloaded files will be unpacked in a sub-directory or directly in the -Output path.
Enabled by default.

##### -Interactive *true/false*
If false, user will never be prompted for input. Enabled by default.
This is useful if experiencing problems with the build agent hanging when expecting input.

##### -Curl *path*
Explicitly sets the path to curl.exe
If omitted, PsGet.ps1 will look for curl.exe in %PROGRAMFILES%\Git\bin\ and %PROGRAMFILES(x86)%\Git\bin

##### -7Zip *path*
Explictly sets the path to 7z.exe
If omitted, PsGet.ps1 will look for 7z.exe in %PROGRAMFILES%\7-Zip and %PROGRAMFILES(x86)%\7-Zip

##### -unzip *path*
Explictly sets the path to unzip.exe
This is only required if you don't have 7zip installed, or have set -7Zip and doesn't have Git for windows installed in %PROGRAMFILES%\Git or %PROGRAMFILES(x86)%\Git

##### -SaveCredentials
When set, PsGet.ps1 will only ask for your credentials, and save it encyrypted to %APPDATA%\PsGet\psget.credential and return.
If PsGet.ps1 is thereafter invoked as normal, without the -Username or -Password parameters set, PsGet.ps1 will load the credentials
from this file.

##### -Force
When set, PsGet.ps1 will always download a new copy, overwriting existing files in the cache.

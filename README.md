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


Example configuration file (psget.config)

    http://middle.of/nowhere/download.if.not.in.cache.zip a1b2c3d4e5f6a7b8c9d1e2f3a4b5c6
    http://middle.of/nowhere/always.download.zip

Example invocation

    .\PsGet.ps1

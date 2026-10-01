# Shared PowerShell Profile (sourced by both PS5 and PS7)
# Equivalent of .bashrc for PowerShell.
#

function get_cac_thumbprint {
    # This function gets the user CAC thumbprint and saves it to ~/.cac_thumbprint for use by refreshcookie

    # Get CAC authentication certificate from the current user's certificate store
    $cacCert = Get-ChildItem -Path cert:\CurrentUser\My | Where-Object {
        $_.Subject -match "OU=DoD" -and
        $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.2"
    } | Sort-Object NotAfter -Descending | Select-Object -First 1

    if ($cacCert) {
        Write-Host "Found CAC authentication certificate:"
        Write-Host "  Thumbprint: $($cacCert.Thumbprint)"
        Write-Host "  Subject:    $($cacCert.Subject)"
        Write-Host "  Expires:    $($cacCert.NotAfter)"

        $certPath = "CurrentUser\My\$($cacCert.Thumbprint)"
        Write-Host ""
        Write-Host "Use this for git config sslCert:"
        Write-Host "  $certPath"

        # Create the ~/.cac_thumbprint file with the thumbprint
        $cacThumbprintFile = Join-Path $env:USERPROFILE ".cac_thumbprint"
        Set-Content -Path $cacThumbprintFile -Value $cacCert.Thumbprint
        Write-Host "Created file $cacThumbprintFile"
    } else {
        Write-Warning "No CAC authentication certificate found in CurrentUser\My"
    }
}

function get_eca_thumbprint {
    # This function gets the user ECA thumbprint and saves it to ~/.eca_thumbprint for use by refreshcookie
    # Supports ECA providers: IdenTrust, Entrust, DigiCert, Symantec/VeriSign

    # Get ECA authentication certificate from the current user's certificate store
    $ecaCert = Get-ChildItem -Path cert:\CurrentUser\My | Where-Object {
        ($_.Subject -match "OU=IdenTrust" -or
         $_.Subject -match "O=IdenTrust" -or
         $_.Subject -match "O=Entrust" -or
         $_.Subject -match "O=DigiCert" -or
         $_.Issuer -match "ECA" -or
         $_.Issuer -match "IdenTrust" -or
         $_.Issuer -match "Entrust") -and
        $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.2"
    } | Sort-Object NotAfter -Descending | Select-Object -First 1

    if ($ecaCert) {
        Write-Host "Found ECA authentication certificate:"
        Write-Host "  Thumbprint: $($ecaCert.Thumbprint)"
        Write-Host "  Subject:    $($ecaCert.Subject)"
        Write-Host "  Issuer:     $($ecaCert.Issuer)"
        Write-Host "  Expires:    $($ecaCert.NotAfter)"

        $certPath = "CurrentUser\My\$($ecaCert.Thumbprint)"
        Write-Host ""
        Write-Host "Use this for git config sslCert:"
        Write-Host "  $certPath"

        # Create the ~/.eca_thumbprint file with the thumbprint
        $ecaThumbprintFile = Join-Path $env:USERPROFILE ".eca_thumbprint"
        Set-Content -Path $ecaThumbprintFile -Value $ecaCert.Thumbprint
        Write-Host "Created file $ecaThumbprintFile"
    } else {
        Write-Warning "No ECA authentication certificate found in CurrentUser\My"
        Write-Host "Searched for certificates from: IdenTrust, Entrust, DigiCert, or issuers containing 'ECA'"
    }
}

function refreshcookie {
    # Use this function to generate a site-specific cookie file for git operations that require CAC authentication.

    # Get the git repo URL - prompt user if not in a git repo
    git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0) {
        $gitRepoUrl = Read-Host "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git)"
        if (-not $gitRepoUrl) { Write-Error "ERROR: No URL provided"; return }
    } else {
        $gitRepoUrl = git config --get remote.origin.url
        if (-not $gitRepoUrl) { Write-Error "ERROR: Run refreshcookie command from a git repo"; return }
    }

    $gitServerDomain = ([System.Uri]$gitRepoUrl).Host
    if (-not $gitServerDomain) { Write-Error "ERROR: Run refreshcookie command from a git repo"; return }

    # Determine the cookie file path
    $cookieFileName = ".git-cookie-$gitServerDomain"
    $cookieFile = "$env:USERPROFILE\$cookieFileName"

    # Check for CAC or ECA thumbprints
    $cacThumbprintFile = "$env:USERPROFILE\.cac_thumbprint"
    $ecaThumbprintFile = "$env:USERPROFILE\.eca_thumbprint"
    $certificateThumbprint = $null

    # Prefer the CAC thumbprint if it exists, otherwise use the ECA thumbprint
    if (Test-Path $cacThumbprintFile) {
        $certificateThumbprint = (Get-Content $cacThumbprintFile -Raw).Trim()
    } elseif (Test-Path $ecaThumbprintFile) {
        $certificateThumbprint = (Get-Content $ecaThumbprintFile -Raw).Trim()
    } else {
        # No CAC or ECA thumbprint - attempt cookie generation using credentials from ~/.netrc
        $netrcPath = "$env:USERPROFILE\.netrc"
        if (-not (Test-Path $netrcPath)) {
            Write-Error "ERROR: No CAC/ECA thumbprint or ~/.netrc file found."
            Write-Host "To generate a cookie, use one of the following:"
            Write-Host "  - CAC:          run [get_cac_thumbprint], then [refreshcookie]"
            Write-Host "  - ECA:          run [get_eca_thumbprint], then [refreshcookie]"
            Write-Host "  - Username/token: create ~/.netrc with an entry for $gitServerDomain"
            Write-Host "      machine $gitServerDomain"
            Write-Host "      login <username>"
            Write-Host "      password <token>"
            return
        }

        Write-Host "No CAC/ECA thumbprint found. Generating cookie using credentials from ~/.netrc..."

        if (Test-Path $cookieFile) { Remove-Item $cookieFile }

        curl.exe --silent -o NUL -L -c "$cookieFile" -b "$cookieFile" --netrc "$gitRepoUrl/info/refs?service=git-upload-pack"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Cookie file for site [$gitServerDomain] generated successfully at: $cookieFile"
        } else {
            Write-Error "ERROR: Failed to generate cookie file [$cookieFile] for site [$gitServerDomain] using user/pass. curl exit code: $LASTEXITCODE"
            Write-Host "Ensure ~/.netrc has an entry for $gitServerDomain"
            Write-Host "  machine $gitServerDomain"
            Write-Host "  login <username>"
            Write-Host "  password <token>"
        }
        return
    }

    # Set the certPath (Windows Schannel requires backslash separators)
    $certPath = "CurrentUser\MY\$certificateThumbprint"

    # Remove existing cookie file if it exists
    if (Test-Path $cookieFile) {
        Remove-Item $cookieFile
    }

    # Use curl to generate the site-specific cookie
    curl.exe --silent -o NUL -L -c "$cookieFile" -b "$cookieFile" --cert "$certPath" "$gitRepoUrl/info/refs?service=git-upload-pack"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Cookie file for site [$gitServerDomain] generated successfully at: $cookieFile"
    } else {
        Write-Error "ERROR: Failed to generate cookie file [$cookieFile] for site [$gitServerDomain]. curl exit code: $LASTEXITCODE"
    }
}

function updategitconfigcac {
    # Use this function to create your .gitconfig entry for this git repo using a CAC certificate by thumbprint

    # Get the git repo URL - prompt user if not in a git repo
    git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0) {
        $gitRepoUrl = Read-Host "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git)"
        if (-not $gitRepoUrl) { Write-Error "ERROR: No URL provided"; return }
    } else {
        $gitRepoUrl = git config --get remote.origin.url
        if (-not $gitRepoUrl) { Write-Error "ERROR: Run updategitconfigcac command from a git repo"; return }
    }

    $gitServerDomain = ([System.Uri]$gitRepoUrl).Host
    if (-not $gitServerDomain) { Write-Error "ERROR: Run updategitconfigcac command from a git repo"; return }

    $dotParts = $gitServerDomain.Split('.')
    if ($dotParts.Count -lt 2) { Write-Error "ERROR: Run updategitconfigcac command from a git repo"; return }
    $baseDomain = ($dotParts | Select-Object -Skip 1) -join '.'

    # Set the cookie filename and path
    $cookieFileName = ".git-cookie-$gitServerDomain"
    $cookieFile = "$env:USERPROFILE\$cookieFileName"

    # Check for CAC thumbprint file
    $cacThumbprintFile = "$env:USERPROFILE\.cac_thumbprint"
    $certificateThumbprint = $null
    if (Test-Path $cacThumbprintFile) {
        $certificateThumbprint = (Get-Content $cacThumbprintFile -Raw).Trim()
    } else {
        Write-Error "ERROR: CAC thumbprint not found."
        Write-Host "Please add your CAC thumbprint to ~/.cac_thumbprint by running the [get_cac_thumbprint] command in PowerShell, or as follows:"
        Write-Host "  Set-Content `"$env:USERPROFILE\.cac_thumbprint`" '<thumbprint>'"
        return
    }

    # Set the certPath (Windows Schannel requires backslash separators)
    $certPath = "CurrentUser\MY\$certificateThumbprint"

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.$baseDomain" 2>$null
    git config --global --remove-section "credential.https://$gitServerDomain" 2>$null

    # Create new config entries for this domain
    git config --global "http.https://*.$baseDomain.followRedirects" true
    git config --global "http.https://*.$baseDomain.sslBackend" schannel
    git config --global "http.https://*.$baseDomain.cookieFile" "$cookieFile"
    if ($baseDomain -like "*.mil") {
        git config --global "http.https://*.$baseDomain.extraheader" "Cookie: consent=true; dashboard=yes"
        git config --global "http.https://*.$baseDomain.saveCookies" "true"
        git config --global "http.https://*.$baseDomain.sslCert" "$certPath"
    }
    git config --global "credential.https://$gitServerDomain.provider" generic

    Write-Host "Completed: Updated .gitconfig for domain [$gitServerDomain] with CAC."
    Write-Host "If this site requires an OAuth2 proxy session cookie, run [refreshcookie] to generate it."
}

function updategitconfigeca {
    # Use this function to create your .gitconfig entry for this git repo using an installed ECA by thumbprint

    # Get the git repo URL - prompt user if not in a git repo
    git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0) {
        $gitRepoUrl = Read-Host "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git)"
        if (-not $gitRepoUrl) { Write-Error "ERROR: No URL provided"; return }
    } else {
        $gitRepoUrl = git config --get remote.origin.url
        if (-not $gitRepoUrl) { Write-Error "ERROR: Run updategitconfigeca command from a git repo"; return }
    }

    $gitServerDomain = ([System.Uri]$gitRepoUrl).Host
    if (-not $gitServerDomain) { Write-Error "ERROR: Run updategitconfigeca command from a git repo"; return }

    $dotParts = $gitServerDomain.Split('.')
    if ($dotParts.Count -lt 2) { Write-Error "ERROR: Run updategitconfigeca command from a git repo"; return }
    $baseDomain = ($dotParts | Select-Object -Skip 1) -join '.'

    # Set the cookie filename and path
    $cookieFileName = ".git-cookie-$gitServerDomain"
    $cookieFile = "$env:USERPROFILE\$cookieFileName"

    # Check for ECA thumbprint file
    $ecaThumbprintFile = "$env:USERPROFILE\.eca_thumbprint"
    $certificateThumbprint = $null
    if (Test-Path $ecaThumbprintFile) {
        $certificateThumbprint = (Get-Content $ecaThumbprintFile -Raw).Trim()
    } else {
        Write-Error "ERROR: ECA thumbprint not found."
        Write-Host "Please add your ECA thumbprint to ~/.eca_thumbprint by running the [get_eca_thumbprint] command in PowerShell, or as follows:"
        Write-Host "  Set-Content `"$env:USERPROFILE\.eca_thumbprint`" '<thumbprint>'"
        return
    }

    # Set the certPath (Windows Schannel requires backslash separators)
    $certPath = "CurrentUser\MY\$certificateThumbprint"

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.$baseDomain" 2>$null
    git config --global --remove-section "credential.https://$gitServerDomain" 2>$null

    # Create new config entries for this domain
    git config --global "http.https://*.$baseDomain.followRedirects" true
    git config --global "http.https://*.$baseDomain.sslBackend" schannel
    git config --global "http.https://*.$baseDomain.cookieFile" "$cookieFile"
    if ($baseDomain -like "*.mil") {
        git config --global "http.https://*.$baseDomain.extraheader" "Cookie: consent=true; dashboard=yes"
        git config --global "http.https://*.$baseDomain.saveCookies" "true"
        git config --global "http.https://*.$baseDomain.sslCert" "$certPath"
    }
    git config --global "credential.https://$gitServerDomain.provider" generic

    Write-Host "Completed: Updated .gitconfig for domain [$gitServerDomain] with ECA."
    Write-Host "If this site requires an OAuth2 proxy session cookie, run [refreshcookie] to generate it."
}

function updategitconfigecafiles {
    # Use this function to create your .gitconfig entry for this git repo using ECA cert and key files
    # Note: Assuming the ECA private key file is encrypted with a passphrase

    # Get the git repo URL - prompt user if not in a git repo
    git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0) {
        $gitRepoUrl = Read-Host "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git)"
        if (-not $gitRepoUrl) { Write-Error "ERROR: No URL provided"; return }
    } else {
        $gitRepoUrl = git config --get remote.origin.url
        if (-not $gitRepoUrl) { Write-Error "ERROR: Run updategitconfigecafiles command from a git repo"; return }
    }

    $gitServerDomain = ([System.Uri]$gitRepoUrl).Host
    if (-not $gitServerDomain) { Write-Error "ERROR: Run updategitconfigecafiles command from a git repo"; return }

    $dotParts = $gitServerDomain.Split('.')
    if ($dotParts.Count -lt 2) { Write-Error "ERROR: Run updategitconfigecafiles command from a git repo"; return }
    $baseDomain = ($dotParts | Select-Object -Skip 1) -join '.'

    # Set the cookie filename and path
    $cookieFileName = ".git-cookie-$gitServerDomain"
    $cookieFile = "$env:USERPROFILE\$cookieFileName"

    # Ask the user to type the path to the ECA crt and key files
    $ecaCertPath = Read-Host "Enter the path to your ECA certificate file (e.g., $env:USERPROFILE\path\to\eca.crt)"
    Write-Host "Note: Assuming the ECA private key file is encrypted with a passphrase"
    $ecaKeyPath = Read-Host "Enter the path to your ECA private key file (e.g., $env:USERPROFILE\path\to\eca.key)"

    # Ensure the provided paths exist
    if (-not (Test-Path $ecaCertPath -PathType Leaf)) { Write-Error "ERROR: ECA certificate file not found at $ecaCertPath"; return }
    if (-not (Test-Path $ecaKeyPath -PathType Leaf)) { Write-Error "ERROR: ECA private key file not found at $ecaKeyPath"; return }

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.$baseDomain" 2>$null
    git config --global --remove-section "credential.https://$gitServerDomain" 2>$null

    # Create new config entries for this domain
    git config --global "http.https://*.$baseDomain.followRedirects" true
    git config --global "http.https://*.$baseDomain.sslBackend" openssl
    git config --global "http.https://*.$baseDomain.cookieFile" "$cookieFile"
    git config --global "http.https://*.$baseDomain.extraheader" "Cookie: consent=true; dashboard=yes"
    git config --global "http.https://*.$baseDomain.saveCookies" "true"
    git config --global "http.https://*.$baseDomain.sslCert" "$ecaCertPath"
    git config --global "http.https://*.$baseDomain.sslKey" "$ecaKeyPath"
    git config --global "http.https://*.$baseDomain.sslCertPasswordProtected" "true"
    git config --global "credential.https://$gitServerDomain.provider" generic

    Write-Host "Completed: Updated .gitconfig for domain [$gitServerDomain] with ECA certificate and key."
}


function updategitconfiguserpass {
    # Use this function to create your .gitconfig entry for this git repo using username and password

    # Get the git repo URL - prompt user if not in a git repo
    git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0) {
        $gitRepoUrl = Read-Host "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git)"
        if (-not $gitRepoUrl) { Write-Error "ERROR: No URL provided"; return }
    } else {
        $gitRepoUrl = git config --get remote.origin.url
        if (-not $gitRepoUrl) { Write-Error "ERROR: Run updategitconfiguserpass command from a git repo"; return }
    }

    $gitServerDomain = ([System.Uri]$gitRepoUrl).Host
    if (-not $gitServerDomain) { Write-Error "ERROR: Run updategitconfiguserpass command from a git repo"; return }

    $dotParts = $gitServerDomain.Split('.')
    if ($dotParts.Count -lt 2) { Write-Error "ERROR: Run updategitconfiguserpass command from a git repo"; return }
    $baseDomain = ($dotParts | Select-Object -Skip 1) -join '.'

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.$baseDomain" 2>$null
    git config --global --remove-section "credential.https://$gitServerDomain" 2>$null

    # Set the cookie filename and path
    $cookieFileName = ".git-cookie-$gitServerDomain"
    $cookieFile = "$env:USERPROFILE\$cookieFileName"

    # Create new config entries for this domain
    git config --global "http.https://*.$baseDomain.followRedirects" true
    git config --global "http.https://*.$baseDomain.cookieFile" "$cookieFile"

    # Disable credential helper for this URL so git falls back to ~/.netrc
    git config --global "credential.https://$gitServerDomain.helper" ""

    Write-Host "Completed: Updated .gitconfig for domain [$gitServerDomain] with username and password."
    Write-Host "If this site requires an OAuth2 proxy session cookie, run [refreshcookie] to generate it."
}

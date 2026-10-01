# .bashrc
#

function refreshcookie() {
    # Use this function to generate a site-specific cookie file for git operations that require CAC authentication.

    # Get the git repo URL - prompt user if not in a git repo
    local gitRepoUrl
    git rev-parse --show-toplevel > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        read -p "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git): " gitRepoUrl
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: No URL provided"; return 1; fi
    else
        gitRepoUrl=$(git config --get remote.origin.url)
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: Run refreshcookie command from a git repo"; return 1; fi
    fi

    local gitServerDomain=$(echo "${gitRepoUrl}" | sed -E 's#^https?://([^/]+)/.*$#\1#')
    if [ -z "${gitServerDomain}" ]; then echo "ERROR: Run refreshcookie command from a git repo"; return 1; fi

    # Determine the base domain and cookie file name
    local baseDomain=$(echo "${gitServerDomain}" | sed -E 's/^[^.]+\.//')
    local cookieFileName=".git-cookie-$gitServerDomain"
    local cookieFile="$HOME/$cookieFileName"

    # Check for CAC or ECA thumbprints
    local cacThumbprintFile="${HOME}/.cac_thumbprint"
    local ecaThumbprintFile="${HOME}/.eca_thumbprint"
    local certificateThumbprint=""

    # Prefer the CAC thumbprint if it exists, otherwise use the ECA thumbprint
    if [ -f "${cacThumbprintFile}" ]; then
        certificateThumbprint=$(cat "${cacThumbprintFile}")
    elif [ -f "${ecaThumbprintFile}" ]; then
        certificateThumbprint=$(cat "${ecaThumbprintFile}")
    else
        # No CAC or ECA thumbprint - attempt cookie generation using credentials from ~/.netrc
        local netrcPath="${HOME}/.netrc"
        if [ ! -f "${netrcPath}" ]; then
            echo "ERROR: No CAC/ECA thumbprint or ~/.netrc file found."
            echo "To generate a cookie, use one of the following:"
            echo "  - CAC:            echo '<thumbprint>' > ~/.cac_thumbprint, then run [refreshcookie]"
            echo "  - ECA:            echo '<thumbprint>' > ~/.eca_thumbprint, then run [refreshcookie]"
            echo "  - Username/token: create ~/.netrc with an entry for ${gitServerDomain}:"
            echo "      machine ${gitServerDomain}"
            echo "      login <username>"
            echo "      password <token>"
            return 1
        fi

        echo "No CAC/ECA thumbprint found. Generating cookie using credentials from ~/.netrc..."

        if [ -f "${cookieFile}" ]; then rm "${cookieFile}"; fi

        curl --silent -o /dev/null -L -c "${cookieFile}" -b "${cookieFile}" --netrc "${gitRepoUrl}/info/refs?service=git-upload-pack"
        local res=$?
        if [ ${res} -eq 0 ]; then
            echo "Cookie file for site [${gitServerDomain}] generated successfully at: ${cookieFile}"
        else
            echo "ERROR: Failed to generate cookie file [${cookieFile}] for site [${gitServerDomain}] using user/pass. curl exit code: ${res}"
            echo "Ensure ~/.netrc has an entry for ${gitServerDomain}:"
            echo "  machine ${gitServerDomain}"
            echo "  login <username>"
            echo "  password <token>"
            return 1
        fi
        return 0
    fi

    # Set the certPath (Windows Schannel requires backslash separators)
    local certPath="CurrentUser\\MY\\${certificateThumbprint}"

    # Remove existing cookie file if it exists
    if [ -f "${cookieFile}" ]; then
        rm "${cookieFile}"
    fi

    # Use curl to generate the site-specific cookie
    curl --silent -o /dev/null -L -c "${cookieFile}" -b "${cookieFile}" --cert "${certPath}" "${gitRepoUrl}/info/refs?service=git-upload-pack"
    local res=$?
    if [ ${res} -eq 58 ] || [ ${res} -eq 0 ]; then
        echo "Cookie file for site [${gitServerDomain}] generated successfully at: ${cookieFile}"
    else
        echo "ERROR: Failed to generate cookie file [${cookieFile}] for site [${gitServerDomain}], curl exited with code [${res}]."
        return 1
    fi
    return 0
}


function updategitconfigcac() {
    # Use this function to create your .gitconfig entry for this git repo using a CAC certificate by thumbprint

    # Get the git repo URL - prompt user if not in a git repo
    local gitRepoUrl
    git rev-parse --show-toplevel > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        read -p "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git): " gitRepoUrl
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: No URL provided"; return 1; fi
    else
        gitRepoUrl=$(git config --get remote.origin.url)
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: Run updategitconfigcac command from a git repo"; return 1; fi
    fi
    
    local gitServerDomain=$(echo "${gitRepoUrl}" | sed -E 's#^https?://([^/]+)/.*$#\1#')
    if [ -z "${gitServerDomain}" ]; then echo "ERROR: Run updategitconfigcac command from a git repo"; return 1; fi
    local baseDomain=$(echo "${gitServerDomain}" | sed -E 's/^[^.]+\.//')
    if [ -z "${baseDomain}" ]; then echo "ERROR: Run updategitconfigcac command from a git repo"; return 1; fi

    # Set the cookie filename and path
    local cookieFileName=".git-cookie-${gitServerDomain}"
    local cookieFile="${HOME}/${cookieFileName}"

    # CAC thumbprint file
    local cacThumbprintFile="${HOME}/.cac_thumbprint"
    local certificateThumbprint=""

    # Check for CAC thumbprint file, ask user to provide if not found
    if [ -f "${cacThumbprintFile}" ]; then
        certificateThumbprint=$(cat "${cacThumbprintFile}")
    else
        echo "ERROR: CAC thumbprint not found."
        echo "Please add your CAC thumbprint to [~/.cac_thumbprint] by running the [get_cac_thumbprint] command in PowerShell, or as follows:"
        echo "echo '<thumbprint>' > ~/.cac_thumbprint"
        return 1
    fi

    # Set the certPath (Windows Schannel requires backslash separators)
    local certPath="CurrentUser\\MY\\${certificateThumbprint}"

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.${baseDomain}" >> /dev/null 2>&1
    git config --global --remove-section "credential.https://${gitServerDomain}" >> /dev/null 2>&1

    # Create new config entries for this domain
    git config --global "http.https://*.${baseDomain}.followRedirects" true
    git config --global "http.https://*.${baseDomain}.sslBackend" schannel
    git config --global "http.https://*.${baseDomain}.cookieFile" "${cookieFile}"
    if [[ "${baseDomain}" == *.mil ]]; then
        git config --global "http.https://*.${baseDomain}.extraheader" "Cookie: consent=true; dashboard=yes"
        git config --global "http.https://*.${baseDomain}.saveCookies" "true"
        git config --global "http.https://*.${baseDomain}.sslCert" "${certPath}"
    fi
    git config --global "credential.https://${gitServerDomain}.provider" generic

    echo "Completed: Updated .gitconfig for domain [${gitServerDomain}] with CAC."
}


function updategitconfigeca() {
    # Use this function to create your .gitconfig entry for this git repo using an installed ECA by thumbprint

    # Get the git repo URL - prompt user if not in a git repo
    local gitRepoUrl
    git rev-parse --show-toplevel > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        read -p "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git): " gitRepoUrl
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: No URL provided"; return 1; fi
    else
        gitRepoUrl=$(git config --get remote.origin.url)
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: Run updategitconfigeca command from a git repo"; return 1; fi
    fi

    local gitServerDomain=$(echo "${gitRepoUrl}" | sed -E 's#^https?://([^/]+)/.*$#\1#')
    if [ -z "${gitServerDomain}" ]; then echo "ERROR: Run updategitconfigeca command from a git repo"; return 1; fi
    local baseDomain=$(echo "${gitServerDomain}" | sed -E 's/^[^.]+\.//')
    if [ -z "${baseDomain}" ]; then echo "ERROR: Run updategitconfigeca command from a git repo"; return 1; fi

    # Set the cookie filename and path
    local cookieFileName=".git-cookie-${gitServerDomain}"
    local cookieFile="${HOME}/${cookieFileName}"

    # ECA thumbprint file
    local ecaThumbprintFile="${HOME}/.eca_thumbprint"
    local certificateThumbprint=""

    # Check for ECA thumbprint file, ask user to provide if not found
    if [ -f "${ecaThumbprintFile}" ]; then
        certificateThumbprint=$(cat "${ecaThumbprintFile}")
    else
        echo "ERROR: ECA thumbprint not found."
        echo "Please add your ECA thumbprint to [~/.eca_thumbprint] by running the [get_eca_thumbprint] command in PowerShell, or as follows:"
        echo "echo '<thumbprint>' > ~/.eca_thumbprint"
        return 1
    fi

    # Set the certPath (Windows Schannel requires backslash separators)
    local certPath="CurrentUser\\MY\\${certificateThumbprint}"

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.${baseDomain}" >> /dev/null 2>&1
    git config --global --remove-section "credential.https://${gitServerDomain}" >> /dev/null 2>&1

    # Create new config entries for this domain
    git config --global "http.https://*.${baseDomain}.followRedirects" true
    git config --global "http.https://*.${baseDomain}.sslBackend" schannel
    git config --global "http.https://*.${baseDomain}.cookieFile" "${cookieFile}"
    if [[ "${baseDomain}" == *.mil ]]; then
        git config --global "http.https://*.${baseDomain}.extraheader" "Cookie: consent=true; dashboard=yes"
        git config --global "http.https://*.${baseDomain}.saveCookies" "true"
        git config --global "http.https://*.${baseDomain}.sslCert" "${certPath}"
    fi
    git config --global "credential.https://${gitServerDomain}.provider" generic

    echo "Completed: Updated .gitconfig for domain [${gitServerDomain}] with ECA."
}


function updategitconfigecafiles() {
    # Use this function to create your .gitconfig entry for this git repo using ECA cert and key files
    # Note: Assuming the ECA private key file is encrypted with a passphrase

    # Get the git repo URL - prompt user if not in a git repo
    local gitRepoUrl
    git rev-parse --show-toplevel > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        read -p "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git): " gitRepoUrl
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: No URL provided"; return 1; fi
    else
        gitRepoUrl=$(git config --get remote.origin.url)
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: Run updategitconfigecafiles command from a git repo"; return 1; fi
    fi

    local gitServerDomain=$(echo "${gitRepoUrl}" | sed -E 's#^https?://([^/]+)/.*$#\1#')
    if [ -z "${gitServerDomain}" ]; then echo "ERROR: Run updategitconfigecafiles command from a git repo"; return 1; fi
    local baseDomain=$(echo "${gitServerDomain}" | sed -E 's/^[^.]+\.//')
    if [ -z "${baseDomain}" ]; then echo "ERROR: Run updategitconfigecafiles command from a git repo"; return 1; fi

    # Set the cookie filename and path
    local cookieFileName=".git-cookie-${gitServerDomain}"
    local cookieFile="${HOME}/${cookieFileName}"

    # Ask the user to type the path to the ECA crt and key files
    read -p "Enter the path to your ECA certificate file (e.g., ${HOME}/path/to/eca.crt): " ecaCertPath
    echo "Note: Assuming the ECA private key file is encrypted with a passphrase"
    read -p "Enter the path to your ECA private key file (e.g., ${HOME}/path/to/eca.key): " ecaKeyPath

    # Ensure the provided paths exist
    if [ ! -f "${ecaCertPath}" ]; then echo "ERROR: ECA certificate file not found at ${ecaCertPath}"; return 1; fi
    if [ ! -f "${ecaKeyPath}" ]; then echo "ERROR: ECA private key file not found at ${ecaKeyPath}"; return 1; fi

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.${baseDomain}" >> /dev/null 2>&1
    git config --global --remove-section "credential.https://${gitServerDomain}" >> /dev/null 2>&1

    # Create new config entries for this domain
    git config --global "http.https://*.${baseDomain}.followRedirects" true
    git config --global "http.https://*.${baseDomain}.sslBackend" openssl
    git config --global "http.https://*.${baseDomain}.cookieFile" "${cookieFile}"
    git config --global "http.https://*.${baseDomain}.extraheader" "Cookie: consent=true; dashboard=yes"
    git config --global "http.https://*.${baseDomain}.saveCookies" "true"
    git config --global "http.https://*.${baseDomain}.sslCert" "${ecaCertPath}"
    git config --global "http.https://*.${baseDomain}.sslKey" "${ecaKeyPath}"
    git config --global "http.https://*.${baseDomain}.sslCertPasswordProtected" "true"
    git config --global "credential.https://${gitServerDomain}.provider" generic

    echo "Completed: Updated .gitconfig for domain [${gitServerDomain}] with ECA certificate and key."
}


function updategitconfiguserpass() {
    # Use this function to create your .gitconfig entry for this git repo using username and password

    # Get the git repo URL - prompt user if not in a git repo
    local gitRepoUrl
    git rev-parse --show-toplevel > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        read -p "Not in a git repo. Enter the https git clone URL (e.g., https://git.example.com/org/repo.git): " gitRepoUrl
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: No URL provided"; return 1; fi
    else
        gitRepoUrl=$(git config --get remote.origin.url)
        if [ -z "${gitRepoUrl}" ]; then echo "ERROR: Run updategitconfiguserpass command from a git repo"; return 1; fi
    fi

    local gitServerDomain=$(echo "${gitRepoUrl}" | sed -E 's#^https?://([^/]+)/.*$#\1#')
    if [ -z "${gitServerDomain}" ]; then echo "ERROR: Run updategitconfiguserpass command from a git repo"; return 1; fi
    local baseDomain=$(echo "${gitServerDomain}" | sed -E 's/^[^.]+\.//')
    if [ -z "${baseDomain}" ]; then echo "ERROR: Run updategitconfiguserpass command from a git repo"; return 1; fi

    # Set the cookie filename and path
    local cookieFileName=".git-cookie-${gitServerDomain}"
    local cookieFile="${HOME}/${cookieFileName}"

    # Remove existing config entries for this domain if they exist
    git config --global --remove-section "http.https://*.${baseDomain}" >> /dev/null 2>&1
    git config --global --remove-section "credential.https://${gitServerDomain}" >> /dev/null 2>&1

    # Create new config entries for this domain
    git config --global "http.https://*.${baseDomain}.followRedirects" true
    git config --global "http.https://*.${baseDomain}.cookieFile" "${cookieFile}"
    # Disable credential helper for this URL so git falls back to ~/.netrc
    git config --global "credential.https://${gitServerDomain}.helper" ""

    echo "Completed: Updated .gitconfig for domain [${gitServerDomain}] with username and password."
    echo "If this site requires an OAuth2 proxy session cookie, run [refreshcookie] to generate it."
}

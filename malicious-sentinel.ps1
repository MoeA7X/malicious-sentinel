param (
    [string]$apiKey = " "
)

# Initialize logging with dynamic path
$Logfile = Join-Path (Get-Location) 'error_log.txt'

# Function for writing to log file
function LogWrite{
   Param ([string]$logstring)
   Add-content $Logfile -value $logstring
}
 
# Filtering for established connections, removing loopbacks & IP6 addresses
$netstatOutput = netstat -ano | findstr ESTABLISHED | findstr -v 127.0.0.1 | findstr -v ::



# Initialize an array to store connection objects
$connections = @()

# Parse the netstat output to extract connection information
$netstatOutput | ForEach-Object {
    try {
        $parts = $_ -split '\s+'
        $remoteAddressParts = $parts[3] -split ':'
        $localAddressParts = $parts[2] -split ':'

        # Check if the RemoteAddress is an IPv6 address and skip if true
        if ($remoteAddressParts[0] -match '.*:.*:.*') {
            continue
        }

        # Get the process name using PID
        $processName = (Get-Process -Id $parts[5]).ProcessName

        # Construct a PSCustomObject to represent the connection
        $connection = [PSCustomObject]@{
            Protocol = $parts[1]
            LocalAddress = $localAddressParts[0]
            LocalPort = $localAddressParts[1]
            RemoteAddress = $remoteAddressParts[0]
            RemotePort = $remoteAddressParts[1]
            State = $parts[4]
            PID = $parts[5]
            ProcessName = $processName
        }

        # Add the connection object to the connections array
        $connections += $connection
    } catch {
        LogWrite "An error occurred while parsing netstat output: $_"    
    }
}

# Loop through each connection to process VirusTotal data (if API key is provided and valid)
function Use-APIKey{
    foreach ($connection in $connections) {
        try {
            if ($apiKey) {
                $virusTotalApiUrl = "https://www.virustotal.com/api/v3/ip_addresses/" + $connection.RemoteAddress

                $headers = @{
                    "x-apiKey" = $apiKey
                }

                $virusTotalResponse = Invoke-RestMethod -Uri $virusTotalApiUrl -Headers $headers -ErrorAction SilentlyContinue

                $connection | Add-Member -MemberType NoteProperty -Name MaliciousVerdicts -Value ($virusTotalResponse.data.attributes.last_analysis_stats.malicious)
                $connection | Add-Member -MemberType NoteProperty -Name Country -Value ($virusTotalResponse.data.attributes.country)
                $connection | Add-Member -MemberType NoteProperty -Name Continent -Value ($virusTotalResponse.data.attributes.continent)
                $connection | Add-Member -MemberType NoteProperty -Name AS_Owner -Value ($virusTotalResponse.data.attributes.as_owner)
            }
        }
        catch {
            LogWrite "An error occurred: $_" 
        }
    }    
}

Use-APIKey

# Convert the processed connections to JSON and write them to the standard output
#$connections | ConvertTo-Json -Compress -ErrorAction SilentlyContinue

#Convert Output to table
$connections | Format-Table Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, PID, ProcessName, MaliciousVerdicts, Country, Continent, AS_Owner
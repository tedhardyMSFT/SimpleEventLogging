<#
.SYNOPSIS
Collection of event logging functions and syntactic helpers.

.DESCRIPTION
Uses the legacy API to log Windows events, so is limited to the "Classic" event channels.
Events are not schematized and payload is logged as a single event string value.



Useful for adding quick & dirty logging. 

.NOTES
Writes event data to screen as well.
If no host console is available, the write-host is disabled.

Initialization errors are logged to the Microsoft-Windows-PowerShell/Operational channel using existing eventIDs (4100,4101,4102)

#>
function Write-InformationEvent {
<# 
.SYNOPSIS
Write-InformationEvent writes an informational event to the local event log and local screen
.DESCRIPTION
Writes a simple text message (not schematized) Informational level event to 
the local Application log using the global outputEventSource.

If the global variable instanceGuid is populated it will prefix the event 
message.

.PARAMETER EventID
A mandatory parameter, this is the EventID for the event.

.PARAMETER Message
An optional parameter (but really you should put something here) is the
text message to be logged.
.EXAMPLE
Write-InformationEvent 100 "Yoo hoo!"
#>
Param
(
        [Parameter(Mandatory=$true)]
        [UInt16]$EventID,
        [Parameter(Mandatory=$false)]
        [string]$Message
)

    # check if global eventlogging variable is set to true (ok to write to eventlog)
    if($Script:EventLoggingEnabled -eq $true)
    {
        # for script runtime instance logging (doesn't have to be a guid, just something unique per script invokation) 
        if ($Script:instanceGuid -ne $null)
        {
            Write-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource -EntryType Information -EventId $EventID -Message "Instance:$($Script:instanceGuid)`n$($Message)";

        }
        else
        {
            Write-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource -EntryType Information -EventId $EventID -Message $Message;
        }
    }
    if ($Script:WriteHostEnabled) {
        Write-Host -ForegroundColor Green "$((get-date).ToString("s")):Informational:$($EventID):$($Message)";
    }

} # function Write-InformationEvent

function Write-WarningEvent {
<# 
.SYNOPSIS
Write-WarningEvent writes an Warning event to the local event log
.DESCRIPTION
Writes a simple text message (not schematized) Warning level event to 
the local Application log using the global outputEventSource.

If the global variable instanceGuid is populated it will prefix the event 
message.

.PARAMETER EventID
A mandatory parameter, this is the EventID for the event.

.PARAMETER Message
An optional parameter (but really you should put something here) is the
text message to be logged.
.EXAMPLE
Write-WarningEvent 200 "Uh oh!"
#>
Param(
    [Parameter(Mandatory=$true)]
        [UInt16]$EventID,
        [Parameter(Mandatory=$false)]
        [string]$Message
)
    # check if global eventlogging variable is set to true (ok to write to eventlog)
    if($Script:EventLoggingEnabled -eq $true)
    {
        # for script runtime instance logging (doesn't have to be a guid, just something unique per script invokation)
        if ($Script:instanceGuid -ne $null)
        {
            Write-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource -EntryType Warning -EventId $EventID -Message "Instance:$($Script:instanceGuid)`n$($Message)";
        }
        else
        {
            Write-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource -EntryType Warning -EventId $EventID -Message $Message;

        }
    }
    if ($Script:WriteHostEnabled) {
        Write-Host -ForegroundColor Yellow "$((get-date).ToString("s")):Warning:$($EventID):$($Message)";
    }
} # function Write-WarningEvent

function Write-ErrorEvent {
<# 
.SYNOPSIS
Write-ErrorEvent writes an Error event to the local event log
.DESCRIPTION
Writes a simple text message (not schematized) Error level event to 
the local Application log using the global outputEventSource.

If the global variable instanceGuid is populated it will prefix the event 
message.

.PARAMETER EventID
A mandatory parameter, this is the EventID for the event.

.PARAMETER Message
An optional parameter (but really you should put something here) is the
text message to be logged.
.EXAMPLE
Write-ErrorEvent 300 "Better bring a bucket!"
#>
Param(
    [Parameter(Mandatory=$true)]
        [UInt16]$EventID,
        [Parameter(Mandatory=$false)]
        [string]$Message
)
    # check if global eventlogging variable is set to true (ok to write to eventlog)
    if($Script:EventLoggingEnabled -eq $true)
    {
        # for script runtime instance logging (doesn't have to be a guid, just something unique per script invokation)
        if ($Script:instanceGuid -ne $null)
        {
            Write-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource -EntryType Error -EventId $EventID -Message "Instance:$($Script:instanceGuid)`n$($Message)";
        }
        else
        {
            Write-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource -EntryType Error -EventId $EventID -Message $Message;
        }
    }
    if ($Script:WriteHostEnabled) {
        Write-Host -ForegroundColor Red "$((get-date).ToString("s")):Error:$($EventID):$($Message)";
    }
} # function Write-ErrorEvent

function Test-eventlogStatus {
<# 
.SYNOPSIS
Checks whether Application event logging can be performed under the supplied event source.
.DESCRIPTION
Checks if the supplied event source exists, if so, sets the Event log flag
to true and returns.

If the event source does not exist and the script is run with Administrator
privileges, the event source is created. Then the Event log flag is set to true
and the script returns.

Otherwise, the Event log flag is set to false, meaning no event log events.

All messages are echoed to console as well, regardless of flag if an output host is available.

.PARAMETER EventSource
A mandatory parameter, this is the event source name that will be
checked and created if needed. This cannot be null or empty.

.PARAMETER CreateInstanceGuid
[switch] if set, events will be logged with a GUID value indicating a specific instance, to help differentiate two instances of the same script running.

.EXAMPLE
Test-EventLogStatus -EventSource "ThisIsMyEventSource" -CreateInstanceGuid

#>
Param(
    [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$EventSource,
        [switch]$CreateInstanceGuid
)
    $Script:eventLogSource = $EventSource;

    [bool]$eventlogSourceExists = $false;
    if($CreateInstanceGuid) {
        $Script:InstanceGuid = ([Guid]::NewGuid()).ToString();
    } else {
        $Script:InstanceGuid = $null;
    }

    try {
    # check if the event source exists (for any event channel - this is a legacy event source, not a modern event provider)
        $eventlogSourceExists = [System.Diagnostics.EventLog]::SourceExists($EventSource);
    } catch {
        ## hijack an existing event and provide warning details there.
        New-WinEvent -ProviderName 'Microsoft-Windows-PowerShell' -id 4100 -Payload("SimpleEventLogging Module: function Test-eventlogStatus","Not enough permissions to check event log sources. Please re-run script with local admin credentials.","Exception Message:$_");
        if ($Script:WriteHostEnabled) {
            Write-Host -ForegroundColor Red "Not enough permissions to check event log sources. Please re-run script with local admin credentials - See Microsoft-Windows-Powershell/Operational channel EventID 4100 for more details..";
        }
    }

    # If the check returned false, time to create the event source.
    if($false -eq $eventlogSourceExists)
    {
        # event source does not exist - need to create it.
        # but first,
        # Administrator level check - cannot create an event source without Admin level permissions
        # this gets the current windows identity/login-session and checks if it is in the built-in role Administrator.
        if ($true -eq ([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        {
            try # keep this scoped to just new-eventlog to avoid confusion
            {
                New-EventLog -LogName $Script:eventLogName -Source $EventSource;
                $Script:eventLogSource = $EventSource;
                # sweet! set the logging flag to true and return
                $Script:EventLoggingEnabled = $true;
                if ($Script:WriteHostEnabled) {
                    Write-Host -ForegroundColor Green "Successfully created event source:$($EventSource)";
                }
                New-WinEvent -ProviderName 'Microsoft-Windows-PowerShell' -id 4101 -Payload("SimpleEventLogging Module: function Test-eventlogStatus","Successfully created event source:$($EventSource)","Success Status");
                return;
            }
            catch
            {
                if ($Script:WriteHostEnabled) {
                    # new-eventlog is the culprit above, can't even log about it!
                    Write-Host -ForegroundColor Red "Exception caught attempting to create event source: $EventSource";
                    Write-Host -ForegroundColor Red  "Exception Message:$_";
                }
                New-WinEvent -ProviderName 'Microsoft-Windows-PowerShell' -id 4100 -Payload("SimpleEventLogging Module: function Test-eventlogStatus","Exception caught attempting to create event source:$($EventSource)","Exception Message:$_");
                # <sadPanda> no events for us, something went wrong.
                $Script:EventLoggingEnabled = $false;
                return;
            }
        }
        else
        {
            # source does't exist and not enough permissions to create it.
            # set logging flag to false.
            if ($Script:WriteHostEnabled) {
                Write-Host -ForegroundColor Red "Event Logging is disabled because required event source does not exist and user running script does not have permissions to create it";
            }
            New-WinEvent -ProviderName 'Microsoft-Windows-PowerShell' -id 4102 -Payload("SimpleEventLogging Module: function Test-eventlogStatus","Event Logging is disabled because required event source does not exist and user running script does not have permissions to create it","Warning Status");
            $Script:EventLoggingEnabled = $false;
            return;
        }
    }
    else
    {
        # Woot! Event source exists, set flag and no other changes needed.
        $Script:EventLoggingEnabled = $true;
        if ($Script:WriteHostEnabled) {
            Write-Host -ForegroundColor Green "Event Source:$($EventSource) already exists!";
        }
        New-WinEvent -ProviderName 'Microsoft-Windows-PowerShell' -id 4100 -Payload("SimpleEventLogging Module: function Test-eventlogStatus","Event Source:$($EventSource) already exists!","Success Status");
    }
} # function Test-eventlogStatus

## definitions for the script to function properly with set-strictmode enabled.
[bool]$Script:EventLoggingEnabled = $false;
[bool]$Script:WriteHostEnabled = $false;
$Script:eventLogSource = [String]::Empty;
$Script:eventLogName = "Application";

## Script initialization - test whether Write-Host is possible or not.
try {
    Write-Host -NoNewline "";
    $Script:WriteHostEnabled = $true;
}
catch {
    ## no output host available, log and disable the WriteHost commands.
    New-WinEvent -ProviderName 'Microsoft-Windows-PowerShell' -id 4100 -Payload("SimpleEventLogging Module: function Test-eventlogStatus","Disabling Write-Host output. Exception:$($_)","Warning Status");
    $Script:WriteHostEnabled = $false;
}

Export-ModuleMember -Function @('Write-InformationEvent','Write-WarningEvent','Write-ErrorEvent','Test-EventLogStatus');
Export-ModuleMember -Cmdlet @('Write-InformationEvent','Write-WarningEvent','Write-ErrorEvent','Test-EventLogStatus');
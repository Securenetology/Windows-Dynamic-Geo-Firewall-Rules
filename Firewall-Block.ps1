# Execute build of Firewall Rules
# Firewall-Block.ps1
# Dax - 04232024
param ($InputFile = "BlockList.txt", $RuleName, $ProfileType = "any", $InterfaceType = "any", [Switch] $DeleteOnly)

# Look for some help arguments, show help, then quit.
if ($InputFile -match '/[?h]') { "`nPlease run 'get-help .\import-firewall-blocklist.ps1 -full' for help on PowerShell 2.0 and later, or just read the script's header in a text editor.`n" ; exit }  

# Get input file and set the name of the firewall rule.
$file = get-item $InputFile -ErrorAction SilentlyContinue # Sometimes rules will be deleted by name and there is no file.
if (-not $? -and -not $DeleteOnly) { "`nCannot find $InputFile, quitting...`n" ; exit } 
if (-not $rulename) { $rulename = $file.basename }  # The '-#1' will be appended later.

# Description will be seen in the properties of the firewall rules.
$description = "Rule created by script on $(get-date). Do not edit rule by hand, it will be overwritten when the script is run again. By default, the name of the rule is named after the input file."

# Any existing firewall rules which match the name are deleted every time the script runs.
"`nDeleting any inbound or outbound firewall rules named like '$rulename-#*'`n"
$currentrules = netsh.exe advfirewall firewall show rule name=all | select-string '^[Rule Name|Regelname]+:\s+(.+$)' | foreach { $_.matches[0].groups[1].value } 
if ($currentrules.count -lt 3) {"`nProblem getting a list of current firewall rules, quitting...`n" ; exit } 
# Note: If you are getting the above error, try editing the regex pattern two lines above to include the 'Rule Name' in your local language.
$currentrules | foreach { if ($_ -like "$rulename-#*"){ netsh.exe advfirewall firewall delete rule name="$_" | out-null } } 

# Don't create the firewall rules again if the -DeleteOnly switch was used.
if ($deleteonly -and $rulename) { "`nReminder: when deleting by name, leave off the '-#1' at the end of the rulename.`n" } 
if ($deleteonly) { exit } 

# Create array of IP ranges; any line that doesn't start like an IPv4/IPv6 address is ignored.
$ranges = get-content $file | where {($_.trim().length -ne 0) -and ($_ -match '^[0-9a-f]{1,4}[\.\:]')} 
if (-not $?) { "`nCould not parse $file, quitting...`n" ; exit } 
$linecount = $ranges.count
if ($linecount -eq 0) { "`nZero IP addresses to block, quitting...`n" ; exit } 

# Now start creating rules with hundreds of IP address ranges per rule.  Testing shows
# that netsh.exe errors begin to occur with more than 400 IPv4 ranges per rule, and 
# this number might still be too large when using IPv6 or the Start-to-End format, so 
# default to only 100 ranges per rule, but feel free to edit the following variable:
$MaxRangesPerRule = 100

$i = 1                     # Rule number counter, when more than one rule must be created, e.g., BlockList-#001.
$start = 1                 # For array slicing out of IP $ranges.
$end = $maxrangesperrule   # For array slicing out of IP $ranges.
do {
    $icount = $i.tostring().padleft(3,"0")  # Used in name of rule, e.g., BlockList-#042.
    
    if ($end -gt $linecount) { $end = $linecount } 
    $textranges = [System.String]::Join(",",$($ranges[$($start - 1)..$($end - 1)])) 

    "`nCreating an  inbound firewall rule named '$rulename-#$icount' for IP ranges $start - $end" 
    netsh.exe advfirewall firewall add rule name="$rulename-#$icount" dir=in action=block localip=any remoteip="$textranges" description="$description" profile="$profiletype" interfacetype="$interfacetype"
    if (-not $?) { "`nFailed to create '$rulename-#$icount' inbound rule for some reason, continuing anyway..."}
    
    "`nCreating an outbound firewall rule named '$rulename-#$icount' for IP ranges $start - $end" 
    netsh.exe advfirewall firewall add rule name="$rulename-#$icount" dir=out action=block localip=any remoteip="$textranges" description="$description" profile="$profiletype" interfacetype="$interfacetype"
    if (-not $?) { "`nFailed to create '$rulename-#$icount' outbound rule for some reason, continuing anyway..."}
    
    $i++
    $start += $maxrangesperrule
    $end += $maxrangesperrule
} while ($start -le $linecount)
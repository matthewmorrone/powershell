Set-Alias subl 'C:\Program Files\Sublime Text 3\sublime_text.exe'
Set-Alias np 'C:WindowsSystem32notepad.exe'
$Shell = $Host.UI.RawUI
$Shell.BackgroundColor = "Black"
$Shell.ForegroundColor = "Green"
Set-Location C:\Users\c-mmorrone
$MaximumHistoryCount = 32KB-1
Clear-Host

function Encrypt
{
	param([Parameter(ValueFromPipeline = $true)]$Text)
		process
	{
		$Text |
		ConvertTo-SecureString -AsPlainText -Force |
		ConvertFrom-SecureString
	}
}


function Play-Sound
{
	# find first available WAV file in Windows
	$WAVPath = Get-ChildItem -Path $env:windir -Filter *.wav -Recurse -ErrorAction SilentlyContinue |
	Select-Object -First 1 -ExpandProperty FullName
	# load file and play it
	$player = New-Object Media.SoundPlayer $WAVPath
	try
	{
		$player.PlayLooping()
		'Doing something...'
		1..100 | ForEach-Object {
			Write-Progress -Activity 'Doing Something. Hang in' -Status $_ -PercentComplete $_
			Start-Sleep -MilliSeconds (Get-Random -Minimum 300 -Maximum 1300)
		}
	}
	finally
	{
		$player.Stop()
	}
}

function Decrypt
{
	param([Parameter(ValueFromPipeline = $true)]$Text)
	process
	{
		$SecureString = $Text |
		ConvertTo-SecureString
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
		[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
	}
}

function Get-Event-Log
{
	Get-EventLog -List | Select-Object -ExpandProperty Entries -ErrorAction SilentlyContinue | Where-Object { $_.EntryType -eq 'Error' }
}
function Show-WebPage
{
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = 'URL to open')]
        $URL
    )
    Start-Process -FilePath iexplore.exe -ArgumentList $URL
}
function Get-System-Info
{
	Get-WmiObject -Class Win32_Processor | Select-Object -Property Name, Number*
}

function Get-LoggedOnUserSession
{
	param ($ComputerName, $Credential)
	Get-WmiObject -Class Win32_LogonSession @PSBoundParameters |
	ForEach-Object {
		$_.GetRelated('Win32_UserAccount') |
		Select-Object -ExpandProperty Caption
	} | Sort-Object -Unique
}
function Get-LoggedOnUser
{
	param ($ComputerName, $Credential)
	Get-WmiObject -Class Win32_ComputerSystem @PSBoundParameters |
	Select-Object -ExpandProperty UserName
}
function Get-IP
{
	$ComputerName = ''
	[System.Net.Dns]::GetHostAddresses($ComputerName).IPAddressToString
}


function Get-IPv4
{
	$ComputerName = ''
	[System.Net.Dns]::GetHostAddresses($ComputerName) |
	Where-Object {
		$_.AddressFamily -eq 'InterNetwork'
	} | Select-Object -ExpandProperty IPAddressToString
}
function Get-IPv6
{
	$ComputerName = ''
	[System.Net.Dns]::GetHostAddresses($ComputerName) |
	Where-Object {
		$_.AddressFamily -eq 'InterNetworkV6'
	} | Select-Object -ExpandProperty IPAddressToString
}


function Get-Links
{
	param([string] $url='')
	$page = Invoke-WebRequest -Uri $url
	$page.Links
}
function Get-Raw
{
	param([string] $url='')
	$page = Invoke-WebRequest -Uri $url
	$page.RawContent
}

$Shell = $Host.UI.RawUI
$Shell.ForegroundColor		 = "White"
$Shell.BackgroundColor		 = "Black"
$Shell.CursorSize				= 100

# $Shell.BufferSize				= (200,5000)
$value = $Shell.BufferSize
$value.Width = 200
$value.Height = 5000
$Shell.BufferSize = $value

# $Shell.WindowSize				= (200,50)
$value = $Shell.WindowSize
$value.Width = 200
$value.Height = 50
$Shell.WindowSize = $value


# Set-Location C:\Users\Matthew\downloads
$MaximumHistoryCount = 32KB-1

Set-Alias -Name wget -Value 'C:\wget\wget.exe' -Option AllScope
Set-Alias subl 'C:\Program Files\Sublime Text 3\sublime_text.exe'
Set-Alias np 'C:\Windows\System32\notepad.exe'
Set-Alias py 'python'
Set-Alias brc 'brc64'

Set-Alias png 'magick mogrify -format -identify png *'
Set-Alias trim 'magick mogrify -trim -identify *.png'
Set-Alias limit 'magick mogrify -resize 500x500> -identify *.png'
Set-Alias svg 'magick mogrify -size 500x500 -background none -format png -identify *.svg'
Set-Alias pad 'magick mogrify -background transparent -gravity center -extent 550x550 -identify *.png'
Set-Alias negate 'magick mogrify +negate *.png'
# mogrify -size 500x500 -background none  -gravity center -extent 550x550 -format png -identify *.svg



function esveen
{
	param([Parameter(ValueFromPipeline = $true)]$path)
	process
	{
		svn update C:/projects/starhunter/stable
		svn update C:/projects/starhunter/branches/node
		svn update C:/projects/eadmin/dev
		svn update C:/projects/eadmin/rc
		svn update C:/projects/eadmin/stable
		svn update C:/projects/eadmin/branches/node
		svn update C:/projects/obrist
		svn update C:/projects/shop
		svn update C:/projects/elunic-sync
	}
}



function folderFix
{
	param([Parameter(ValueFromPipeline = $true)]$execute)
	process
	{
		brc64 /nofiles /recursive /replaceci:" ":"_" /REGEXP:'(.*)([a-z0-9])([A-Z])(.*)':'\1\2_\3\4' /replaceci:".":"_" /REGEXP:'(.*)([A-Z0-9]{2})([a-z]{2})(.*)':'\1\2_\3\4' /changecase:l $execute
	}
}
function fileFix
{
	param([Parameter(ValueFromPipeline = $true)]$execute)
	process
	{
		# brc64 /nofolders /recursive /REGEXP:"(.*)__(.*)":"\1_\2" /replaceci:" ":"_" /replaceci:"-":"_" /replaceci:"@":"_" /replaceci:".":"_" /replaceci:"~":"_" /changecase:"l" /appendfolder:"p":"_":"1" $execute
		brc64 /nofolders /recursive /REGEXP:"(.*)__(.*)":"\1_\2" /replaceci:" ":"_" /replaceci:"-":"_" /replaceci:"@":"_" /replaceci:".":"_" /replaceci:"~":"_" /changecase:"l" $execute
	}
}

function resize
{
	param([Parameter(ValueFromPipeline = $true)]$size)
	process
	{
		if(!($size)){
			$size=200
		}
		$dimensions = "{0}x{0}" -f $size
		magick mogrify -resize $dimensions -identify *.png
	}
}




function FixDimensions
{
	param([Parameter(ValueFromPipeline = $true)]$path)
	process
	{
		if(!($path)){
			$path=$pwd
		}
		$files = Get-ChildItem $path -Filter *.png  | select FullName # -Recurse
		$count = $files.Count
		$i = $count - 1
		$outfile = ""
		while ($i -gt 0) {
			$outfile = $files[$i].FullName
			# magick convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -composite $outfile
			magick convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -extent 500x500 -background none -composite $outfile
			if ($i % 10 -eq 0) {
				Write-Output "$i	$outfile"
			}
			$i--
		}
	}
}

function sublime
{
	param([Parameter(ValueFromPipeline = $true)]$path)
	process
	{
		if(!($path)){
			$path=$pwd
		}
		echo $path
		subl $path
	}
}

function Reload-Profile {
  @(
	 $Profile.AllUsersAllHosts,
	 $Profile.AllUsersCurrentHost,
	 $Profile.CurrentUserAllHosts,
	 $Profile.CurrentUserCurrentHost
  ) | % {
	 if(Test-Path $_){
		Write-Verbose "Running $_"
		. $_
	 }
  }  
}

function RemoveEmptyDirectories
{
	# Get-ChildItem -recurse | Where {!$_.PSIsContainer -and `
	# $_.LastWriteTime -lt (get-date).AddDays(-31)} | Remove-Item -whatif

	# Get-ChildItem -recurse | Where {$_.PSIsContainer -and `
	# @(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 0} |
	# Remove-Item -recurse -whatif
	param([Parameter(ValueFromPipeline = $true)]$path)
	process
	{
		if(!($path)){
			$path=$pwd
		}
		do {
			$dirs = gci $path -directory -recurse | Where { (gci $_.fullName).count -eq 0 } | select -expandproperty FullName
			$dirs | Foreach-Object { Remove-Item $_ }
		} while ($dirs.count -gt 0)
	}
}


function PortView
{
	$proc = @{};
	Get-Process | ForEach-Object { $proc.Add($_.Id, $_) };
	netstat -aon | Select-String "\s*([^\s]+)\s+([^\s]+):([^\s]+)\s+([^\s]+):([^\s]+)\s+([^\s]+)?\s+([^\s]+)" | ForEach-Object {
		$g = $_.Matches[0].Groups;
		New-Object PSObject |
			Add-Member @{ Protocol =			  $g[1].Value  } -PassThru |
			Add-Member @{ LocalAddress =		 $g[2].Value  } -PassThru |
			Add-Member @{ LocalPort =	  [int]$g[3].Value  } -PassThru |
			Add-Member @{ RemoteAddress =		$g[4].Value  } -PassThru |
			Add-Member @{ RemotePort =			$g[5].Value  } -PassThru |
			Add-Member @{ State =				  $g[6].Value  } -PassThru |
			Add-Member @{ PID =			  [int]$g[7].Value  } -PassThru |
			Add-Member @{ Process = $proc[[int]$g[7].Value] } -PassThru;
	#
	} | Format-Table Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State -GroupBy @{Name='Process';Expression={$p=$_.Process;@{$True=$p.ProcessName; $False=$p.MainModule.FileName}[$p.MainModule -eq $Null] + ' PID: ' + $p.Id}} -AutoSize
}

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

# -----------------------------------------------------------------------------
# Gets all the metadata and returns a custom PSObject it is a bit slow right now, because I need to check all 266 fields for each file, and then create a custom object and emit it.
# If used, use a variable to store the returned objects before attempting to do any sorting, filtering, and formatting of the output.
# To do a recursive lookup of all metadata on all files, use this type of syntax to call the function:
# Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName
# note: this MUST point to a folder, and not to a file.
# -----------------------------------------------------------------------------
Function Get-FileMetaData
{
	Param([string[]]$folder)
	foreach($sFolder in $folder)
	{
		$a = 0
		$objShell = New-Object -ComObject Shell.Application
		$objFolder = $objShell.namespace($sFolder)

		foreach ($File in $objFolder.items())
		{
			$FileMetaData = New-Object PSOBJECT
			for ($a ; $a  -le 266; $a++)
			{
				if($objFolder.getDetailsOf($File, $a))
				{
						$hash += @{$($objFolder.getDetailsOf($objFolder.items, $a))  = $($objFolder.getDetailsOf($File, $a)) }
						$FileMetaData | Add-Member $hash
						$hash.clear()
				} #end if
			} #end for
			$a=0
			$FileMetaData
		} #end foreach $file
  } #end foreach $sfolder
} #end Get-FileMetaData


# Clear-Host

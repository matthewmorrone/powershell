$Shell = $Host.UI.RawUI
$Shell.ForegroundColor       = "White"
$Shell.BackgroundColor       = "Black"
$Shell.CursorSize            = 100

# $Shell.BufferSize            = (200,5000)
$value = $Shell.BufferSize
$value.Width = 200
$value.Height = 5000
$Shell.BufferSize = $value

# $Shell.WindowSize            = (200,50)
$value = $Shell.WindowSize
$value.Width = 200
$value.Height = 50
$Shell.WindowSize = $value


Set-Location C:\Users\Matthew\downloads
$MaximumHistoryCount = 32KB-1

Set-Alias -Name wget -Value 'C:\wget\wget.exe' -Option AllScope
Set-Alias subl 'C:\Program Files\Sublime Text 3\sublime_text.exe'
Set-Alias np 'C:\Windows\System32\notepad.exe'
Set-Alias brc 'BRC64'



function Sublime
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

function RemoveEmptyDirectories
{
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

function FixDimensions
{
	param([Parameter(ValueFromPipeline = $true)]$path)
	process
	{
		if(!($path)){
			$path=$pwd
		}
		$files = Get-ChildItem $path -Filter *.png
		$count = $files.Count
		$i = $count - 1
		$outfile = ""
		while ($i -gt 0) {
			$outfile = $files[$i].Name
			convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -composite $outfile
			if ($i % 10 -eq 0) {
				Write-Output "$i	$outfile"
			}
			$i--
		}
	}
}

function PortView
{
	$proc = @{};
	Get-Process | ForEach-Object { $proc.Add($_.Id, $_) };
	netstat -aon | Select-String "\s*([^\s]+)\s+([^\s]+):([^\s]+)\s+([^\s]+):([^\s]+)\s+([^\s]+)?\s+([^\s]+)" | ForEach-Object {
		$g = $_.Matches[0].Groups;
		New-Object PSObject | 
			Add-Member @{ Protocol =           $g[1].Value  } -PassThru |
			Add-Member @{ LocalAddress =       $g[2].Value  } -PassThru |
			Add-Member @{ LocalPort =     [int]$g[3].Value  } -PassThru |
			Add-Member @{ RemoteAddress =      $g[4].Value  } -PassThru |
			Add-Member @{ RemotePort =         $g[5].Value  } -PassThru |
			Add-Member @{ State =              $g[6].Value  } -PassThru |
			Add-Member @{ PID =           [int]$g[7].Value  } -PassThru |
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
# Script: Get-FileMetaDataReturnObject.ps1
# Author: ed wilson, msft
# Date: 01/24/2014 12:30:18
# Keywords: Metadata, Storage, Files
# comments: Uses the Shell.APplication object to get file metadata
# Gets all the metadata and returns a custom PSObject
# it is a bit slow right now, because I need to check all 266 fields
# for each file, and then create a custom object and emit it.
# If used, use a variable to store the returned objects before attempting
# to do any sorting, filtering, and formatting of the output.
# To do a recursive lookup of all metadata on all files, use this type
# of syntax to call the function:
# Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName
# note: this MUST point to a folder, and not to a file.
# -----------------------------------------------------------------------------
Function Get-FileMetaData
{
  <#
   .Synopsis
	This function gets file metadata and returns it as a custom PS Object 
   .Description
	This function gets file metadata using the Shell.Application object and
	returns a custom PSObject object that can be sorted, filtered or otherwise
	manipulated.
   .Example
	Get-FileMetaData -folder "e:\music"
	Gets file metadata for all files in the e:\music directory
   .Example
	Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName
	This example uses the Get-ChildItem cmdlet to do a recursive lookup of 
	all directories in the e:\music folder and then it goes through and gets
	all of the file metada for all the files in the directories and in the 
	subdirectories.  
   .Example
	Get-FileMetaData -folder "c:\fso","E:\music\Big Boi"
	Gets file metadata from files in both the c:\fso directory and the
	e:\music\big boi directory.
   .Example
	$meta = Get-FileMetaData -folder "E:\music"
	This example gets file metadata from all files in the root of the
	e:\music directory and stores the returned custom objects in a $meta 
	variable for later processing and manipulation.
   .Parameter Folder
	The folder that is parsed for files 
   .Notes
	NAME:  Get-FileMetaData
	AUTHOR: ed wilson, msft
	LASTEDIT: 01/24/2014 14:08:24
	KEYWORDS: Storage, Files, Metadata
	HSG: HSG-2-5-14
   .Link
	 Http://www.ScriptingGuys.com
 #Requires -Version 2.0
 #>
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
			 $hash += @{$($objFolder.getDetailsOf($objFolder.items, $a))  =
				   $($objFolder.getDetailsOf($File, $a)) }
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

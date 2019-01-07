# & "C:\Program Files (x86)\GnuWin32\bin\wget.exe" https://lms.interskill.com/ --no-check-certificate
# Set-Alias wget & "C:\Program Files (x86)\GnuWin32\bin\wget.exe"

Set-Location C:\Users\morronm\Downloads
Set-Alias -Name wget -Value "C:\Program Files (x86)\GnuWin32\bin\wget.exe" -Option AllScope


Set-Alias -Name php -Value "C:\xampp\php\php.exe" -Option AllScope


# --no-check-certificate
# -i file, --input-file=file
# -B URL, --base=URL
# -O file, --output-document=file
# https://www.computerhope.com/unix/wget.htm

# wget "https://lms.interskill.com/student/enrollments_current.asp" --no-check-certificate
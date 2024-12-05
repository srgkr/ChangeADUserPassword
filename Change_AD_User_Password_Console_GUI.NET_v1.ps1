## на основе https://superuser.com/questions/1196477/allow-users-to-change-expired-password-via-remote-desktop-connection
##https://serverfault.com/questions/570476/how-can-a-standard-windows-user-change-their-password-from-the-command-line/
##https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2022-ps
##https://serverfault.com/questions/779201/changing-other-user-password-from-command-line
##https://blog.netwrix.com/2023/03/24/set-adaccountpassword-powershell-cmdlet/
##https://learn.microsoft.com/ru-ru/archive/blogs/gary/using-microsofts-new-ad-powershell-cmdlets
## обновляемое расположение https://github.com/srgkr/ChangeADUserPassword

param(
    [switch]$Help,
    [switch]$Console,
    [switch]$Netapi32,
    [switch]$Adsi,
    [switch]$ADModule
)

# Функция вывода справки
function Show-Help {
    Write-Host "Изменение пароля пользователя Active Directory различными методами, поддержка графического отображения через .NET и работа в консольном режиме"
    Write-Host ""
    Write-Host "Использование: `$PSCommandPath [-Help] [-Console] [-Netapi32] [-Adsi] [-ADModule]"
    Write-Host ""
    Write-Host "Команды:"
    Write-Host "  -Help                  Отображение справки"
    Write-Host "  -Console               Run in console mode (Method Netapi32)"
    Write-Host "  -Netapi32              Run in console mode (Ввод пароля в открытом виде! Method Netapi32)"
    Write-Host "  -Adsi                  Run in console mode (Ввод пароля в открытом виде! Method ADSI)"
    Write-Host "  -ADModule              Run in console mode (Безопасный метод Set-ADAccountPassword, требуется AD DS Snap-Ins или RSAT)"
}

function Set-PasswordRemotely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)][string] $OldPassword,
        [Parameter(Mandatory = $true)][string] $NewPassword,
        [Parameter(Mandatory = $true)][alias('DC', 'Server', 'ComputerName')][string] $DomainController
    )
    $DllImport = @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
public static extern bool NetUserChangePassword(string domain, string username, string oldpassword, string newpassword);
'@
    $NetApi32 = Add-Type -MemberDefinition $DllImport -Name 'NetApi32' -Namespace 'Win32' -PassThru
try {
    if ($NetApi32::NetUserChangePassword($DomainController, $UserName, $OldPassword, $NewPassword)) {
        # Проверка кода ошибки после успешного вызова функции
        $error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($error -eq 0) {
            Write-Output "Процедура смены пароля запущена"
        } else {
            Write-Warning "Процедура смены пароля запущена, но функцией возвращён код ошибки $($error)"
        }
    } else {
        $error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Password change failed. Error code: $($error). Please try again."
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
}

function Set-PasswordRemotely-ADSI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)][string] $OldPassword,
        [Parameter(Mandatory = $true)][string] $NewPassword,
        [Parameter(Mandatory = $true)][alias('DC', 'Server',  'ComputerName')][string] $DomainController
    )
$domain = "DC=" + ($domainController -replace '\.', ',DC=')

$ADSystemInfo = New-Object -ComObject ADSystemInfo
$type = $ADSystemInfo.GetType()

# Добавляем свойство distinguishedName чтобы найти УЗ в нужном для изменения пароля формате
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$domain"
$searcher.Filter = "(sAMAccountName=$username)"
$searcher.PropertiesToLoad.Add("distinguishedName") 

$result = $searcher.FindOne()

if ($result) {
    $distinguishedName = [string]$result.Path
    $user = [ADSI]"$distinguishedName"
} else {
    Write-Warning "User '$username' not found."
}

# меняем пароль
$user.ChangePassword( $oldPassword, $newPassword)

} # end func adsi

## start gui
function Get-InputForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Password Change"
    $form.Size = New-Object System.Drawing.Size(300, 370) # Увеличен размер для кнопки
    $form.StartPosition = "CenterScreen"

    $userNameLabel = New-Object System.Windows.Forms.Label
    $userNameLabel.Text = "Username:"
    $userNameLabel.Location = New-Object System.Drawing.Point(10, 10)
    $userNameLabel.AutoSize = $true
    $form.Controls.Add($userNameLabel)

    $userNameTextBox = New-Object System.Windows.Forms.TextBox
    $userNameTextBox.Location = New-Object System.Drawing.Point(10, 30)
    $userNameTextBox.Size = New-Object System.Drawing.Size(260, 20)
    $userNameTextBox.Text = $env:USERNAME
    $form.Controls.Add($userNameTextBox)

    $oldPasswordLabel = New-Object System.Windows.Forms.Label
    $oldPasswordLabel.Text = "Old Password:"
    $oldPasswordLabel.Location = New-Object System.Drawing.Point(10, 60)
    $oldPasswordLabel.AutoSize = $true
    $form.Controls.Add($oldPasswordLabel)

    $oldPasswordTextBox = New-Object System.Windows.Forms.TextBox
    $oldPasswordTextBox.Location = New-Object System.Drawing.Point(10, 80)
    $oldPasswordTextBox.Size = New-Object System.Drawing.Size(260, 20)
    $oldPasswordTextBox.PasswordChar = '*'
    $form.Controls.Add($oldPasswordTextBox)

    $newPasswordLabel = New-Object System.Windows.Forms.Label
    $newPasswordLabel.Text = "New Password:"
    $newPasswordLabel.Location = New-Object System.Drawing.Point(10, 110)
    $newPasswordLabel.AutoSize = $true
    $form.Controls.Add($newPasswordLabel)

    $newPasswordTextBox = New-Object System.Windows.Forms.TextBox
    $newPasswordTextBox.Location = New-Object System.Drawing.Point(10, 130)
    $newPasswordTextBox.Size = New-Object System.Drawing.Size(260, 20)
    $newPasswordTextBox.PasswordChar = '*'
    $form.Controls.Add($newPasswordTextBox)

    $domainControllerLabel = New-Object System.Windows.Forms.Label
    $domainControllerLabel.Text = "Domain Controller:"
    $domainControllerLabel.Location = New-Object System.Drawing.Point(10, 160)
    $domainControllerLabel.AutoSize = $true
    $form.Controls.Add($domainControllerLabel)

    $domainControllerTextBox = New-Object System.Windows.Forms.TextBox
    $domainControllerTextBox.Location = New-Object System.Drawing.Point(10, 180)
    $domainControllerTextBox.Size = New-Object System.Drawing.Size(260, 20)
    $domainControllerTextBox.Text = $env:USERDNSDOMAIN
    $form.Controls.Add($domainControllerTextBox)

# GroupBox для радио-кнопок
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = "Method"
    $groupBox.Location = New-Object System.Drawing.Point(10, 210)
    $groupBox.Size = New-Object System.Drawing.Size(260, 90)
    $form.Controls.Add($groupBox)

    # Радио-кнопки
    $radioButton1 = New-Object System.Windows.Forms.RadioButton
    $radioButton1.Text = "1. netapi32.dll::NetUserChangePassword"
    $radioButton1.Location = New-Object System.Drawing.Point(10, 20)
    $radioButton1.Size = New-Object System.Drawing.Size(240, 20)
    $radioButton1.Checked = $true # Выбрана по умолчанию
    $groupBox.Controls.Add($radioButton1)

    $radioButton2 = New-Object System.Windows.Forms.RadioButton
    $radioButton2.Text = "2. ADSI LDAP ADSystemInfo"
    $radioButton2.Location = New-Object System.Drawing.Point(10, 40)
    $radioButton2.Size = New-Object System.Drawing.Size(240, 20)
    $groupBox.Controls.Add($radioButton2)

    $radioButton3 = New-Object System.Windows.Forms.RadioButton
    $radioButton3.Text = "3. Module ActiveDirectory"
    $radioButton3.Location = New-Object System.Drawing.Point(10, 60)
    $radioButton3.Size = New-Object System.Drawing.Size(240, 20)
    $groupBox.Controls.Add($radioButton3)
#
<##>
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(195, 305)
    $okButton.Size = New-Object System.Drawing.Size(75, 23)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okButton)
    $form.AcceptButton = $okButton # Кнопка OK будет активироваться при нажатии Enter

 Register-ObjectEvent $form FormClosing -Action {
        if ($_.SourceEventArgs.CloseReason -eq "UserClosing" -and $form.DialogResult -eq "None") {
            $_.SourceEventArgs.Cancel = $true
        }
    }

##    $form.FormClosing = {
    # Установка обработчика FormClosing ДО ShowDialog()
#    $form.FormClosing += {
#        param($sender, $e)
#        if ($e.CloseReason -eq "UserClosing" -and $form.DialogResult -eq "None") {
#            $e.Cancel = $true
#        }
#    }

    $result = $form.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return [PSCustomObject]@{
            UserName = $userNameTextBox.Text
            OldPassword = $oldPasswordTextBox.Text
            NewPassword = $newPasswordTextBox.Text
            DomainController = $domainControllerTextBox.Text
##            Method = if ($radioButton1.Checked) {1} elseif ($radioButton2.Checked) {2} else {3} <##>
    Method = switch ($true) {
        $radioButton1.Checked { 1 }
        $radioButton2.Checked { 2 }
        $radioButton3.Checked { 3 }
        default {
            Write-Warning "No method selected. Using default method (1)."
            1
        }
        } # switch
        } # pscustomobject
    } else {
        return $null # Возвращаем null, если форма закрыта без нажатия OK
    }
}
## end gui

# Функция запуска GUI
function Run-GUI {
Add-Type -AssemblyName System.Windows.Forms
# Получение данных из формы
$input = Get-InputForm

# Проверка на пустые поля и null
if (-not $input) {
    Write-Warning "Form closed without submitting data."
    exit
}
elseif (-not ($input.UserName) -or -not ($input.OldPassword) -or -not ($input.NewPassword) -or -not ($input.DomainController)) {
    Write-Warning "Заполните все данные в форме"
    exit
}

#Write-Host "Method $($input.Method)"
    switch ($($input.Method)) {
        1 {
            Set-PasswordRemotely -UserName "$($input.UserName)" -OldPassword "$($input.OldPassword)" -NewPassword "$($input.NewPassword)" -DomainController "$($input.DomainController)"
        }
        2 {
            Set-PasswordRemotely-ADSI -UserName "$($input.UserName)" -OldPassword "$($input.OldPassword)" -NewPassword "$($input.NewPassword)" -DomainController "$($input.DomainController)"
        }
        3 {
            Set-PasswordRemotely-ADModule -UserName "$($input.UserName)" -OldPassword ("$($input.OldPassword)"|ConvertTo-SecureString -AsPlainText -Force) -NewPassword ("$($input.NewPassword)"|ConvertTo-SecureString -AsPlainText -Force) -DomainController "$($input.DomainController)"
        }
        default {
            Write-Warning "Invalid method selected."
        }
    
} 

} ## end run_gui

## чтение с параметрами по умолчанию
function Read-HostWithDefault {
    param(
        [string]$Prompt,
        [string]$DefaultValue
    )
    $value = Read-Host -Prompt "$Prompt (По умолчанию $DefaultValue (нажать ENTER))"
    if (-not $value) {
        return $DefaultValue
    } else {
        return $value
    }
}


# Функция запуска консольного режима (метод 1, 2)
function Run-Console {
    param(
        [int]$Method
    )
# Запрос параметров у пользователя
try {


    $UserName = Read-HostWithDefault -Prompt "Введите имя пользователя (например i.familiya)" -DefaultValue $env:USERNAME
    $OldPassword = Read-Host -Prompt "Введите старый пароль"
    $NewPassword = Read-Host -Prompt "Введите новый пароль"
    $DomainController = Read-HostWithDefault -Prompt "Введите полное имя домена AD" -DefaultValue $env:USERDNSDOMAIN

    # Вызов функции изменения пароля в зависимости от метода
    switch ($Method) {
        1 { Set-PasswordRemotely -UserName "$($UserName)" -OldPassword "$($OldPassword)" -NewPassword "$($NewPassword)" -DomainController "$($DomainController)" }
        2 { Set-PasswordRemotely-ADSI -UserName "$($UserName)" -OldPassword "$($OldPassword)" -NewPassword "$($NewPassword)" -DomainController "$($DomainController)" }
        default { Write-Warning "Invalid method selected." }
    }
    # Вызов функции с параметрами

}
catch {
    Write-Error $_.Exception.Message
}

}

function Set-PasswordRemotely-ADModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)] $OldPassword,
        [Parameter(Mandatory = $true)] $NewPassword,
        [Parameter(Mandatory = $true)][alias('DC', 'Server',  'ComputerName')][string] $DomainController
    )

try {
    # Изменение пароля с помощью Set-ADAccountPassword
    Import-module ActiveDirectory
    Write-Host "Процедура смены пароля запущена"
Set-ADAccountPassword -Identity $username -NewPassword $newPassword -OldPassword $oldPassword -server $DomainController –PassThru

}
catch {
    Write-Error "Password change failed: $($_.Exception.Message)"
}

} ## end Set-PasswordRemotely-ADModule

# Функция запуска консольного режима (метод 3)
function Run-Console_ADModule {
    Import-module ActiveDirectory
    # Запрос данных от пользователя в консоли
    $UserName = Read-HostWithDefault -Prompt "Введите имя пользователя (например i.familiya)" -DefaultValue $env:USERNAME
    $oldPassword = Read-Host -AsSecureString -Prompt "Введите старый пароль"
    $newPassword = Read-Host -AsSecureString -Prompt "Введите новый пароль"
    $DomainController = Read-HostWithDefault -Prompt "Введите полное имя домена AD" -DefaultValue $env:USERDNSDOMAIN
try {
    # Изменение пароля с помощью Set-ADAccountPassword
    Write-Host "Процедура смены пароля запущена"
Set-ADAccountPassword -Identity $username -NewPassword $newPassword -OldPassword $oldPassword -server $DomainController –PassThru
##    Set-ADAccountPassword -Identity $username -NewPassword $newPassword -OldPassword $oldPassword -server $DomainController 
##    Set-ADAccountPassword -Reset -Identity $username -NewPassword $newPassword -server $DomainController –PassThru
##    Unlock-ADAccount –Identity $username

}
catch {
    Write-Error "Password change failed: $($_.Exception.Message)"
}


} ## end function Run-Console_ADModule


## Main
if ($Help) {
    Show-Help
} elseif ($Console -or $Netapi32) {
    Run-Console -Method 1
} elseif ($Adsi) {
    Run-Console -Method 2
} elseif ($ADModule) {
    Run-Console_ADModule
} else {
    Run-GUI
}

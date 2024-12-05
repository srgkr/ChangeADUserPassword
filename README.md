# ChangeADUserPassword
Изменение пароля пользователя Active Directory различными методами, поддержка графического отображения через .NET и работа в консольном режиме

По умолчанию запускается в графическом режиме. 
Команды для консольного режима:
  -Help                  Отображение справки
  -Console               Run in console mode (Method Netapi32)
  -Netapi32              Run in console mode (Ввод пароля в открытом виде! Method Netapi32)
  -Adsi                  Run in console mode (Ввод пароля в открытом виде! Method ADSI)
  -ADModule              Run in console mode (Безопасный метод Set-ADAccountPassword, требуется AD DS Snap-Ins или RSAT)

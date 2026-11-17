# Wskaźniki incydentu (IOC)

| Wskaźnik / artefakt | Znaczenie |
| --- | --- |
| `hildegardsfarm.com` | Historyczne powiązanie z adresem serwera FTP i subdomenami niosącymi kodowane dane |
| `*.hildegardsfarm.com` | Wzorzec nazw DNS zawierających fragmenty danych |
| `160.153.91.7:21` | Serwer udanych pobrań i wysyłek FTP |
| `45.77.65.211:443` | Adres wskazany w downloaderze i w ruchu procesu PowerShell |
| `jsmith@urinalysis.com` | Nadawca podejrzanych wiadomości |
| `invoice.zip` | Archiwum dostarczane w kampanii, 16 495 bajtów |
| `invoice.doc` | Dokument ze złośliwymi makrami VBA |
| `Updater` | Nazwa zadania harmonogramu na `venus` |
| `HKLM\Software\Microsoft\Network\debug` | Wartość rejestru przechowująca zakodowany skrypt |

Adres `185.83.51.21` występuje w nagłówku SMTP, natomiast `4.4.4.4`, `216.69.185.42` i `208.109.255.42` są elementami obserwowanej infrastruktury DNS. Ich udział w logach nie stanowi automatycznej podstawy do blokady.

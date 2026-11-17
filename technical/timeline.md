# Oś czasu incydentu

Poniższa tabela służy do szybkiej weryfikacji przebiegu incydentu. Pełniejsza chronologia znajduje się w §104 Evidence Journal.

| Data i czas UTC | Zdarzenie | Evidence |
| --- | --- | --- |
| 24.08, 03:27\:14-03\:27:33 | Cztery wiadomości `Invoice` z `invoice.zip` | 07, 15 |
| 24.08, 03:29:08 | WMI → PowerShell na `wrk-btun` | 23F |
| 24.08, 03:36:14 | `hildegardsfarm.com` wskazuje `160.153.91.7` w odpowiedzi DNS | 25AV |
| 24.08, 03\:36-03\:37 | Siedem pobrań FTP na `wrk-btun` | 25AS |
| 24.08, 03:55\:13-03\:55:14 | WMI → PowerShell na `wrk-klagerf` i `venus` | 23F |
| 24.08, 03:55:25 | PowerShell na `venus` inicjuje TCP do `45.77.65.211:443` | 24A |
| 24.08, 03\:59-04\:00 | Siedem pobrań FTP na `wrk-klagerf` | 25AS |
| 24.08, 04:12:36 | Zadanie `Updater` i zapis `debug` na `venus` | 24E, 24I, 24K |
| 26.08, 05:28:25 | Udany `STOR frothly_passwords.kdbx` | 25AT |
| 26.08, 05\:41-06\:45 | Pozostałe wysyłki FTP z `wrk-btun` | 25AT |
| 26.08, 05\:59-06\:50 | `download_py.vbs`, `cscript.exe`, próba instalacji Python MSI, uruchomienie `dns.py` na `venus` | 25A-25J |
| 26.08, 06\:50-07\:09 | Zakodowane subdomeny `hildegardsfarm.com` z `venus` | 25M, 25P |
| 26.08, 06\:50-08\:25 | 424 identyczne FQDN w dwóch grupach ruchu DNS | 25BF |

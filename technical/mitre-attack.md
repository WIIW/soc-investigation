# MITRE ATT&CK Enterprise v20.1

**C** oznacza potwierdzone zachowanie, a **P** wiarygodną próbę lub technikę prawdopodobną. Jest to ta sama skala co w Evidence Journal (§105).

| Technika | Zachowanie i źródło |
| --- | --- |
| `T1566.001` Spearphishing Attachment | Cztery wiadomości `Invoice` ze złośliwym dokumentem w ZIP (C) |
| `T1059.005` Visual Basic | VBA w `invoice.doc` i uruchomienie VBS na `venus` (C) |
| `T1047` Windows Management Instrumentation | WMI uruchamia PowerShell (C) |
| `T1059.001` PowerShell | Zakodowane polecenia na trzech hostach (C) |
| `T1027.010` Command Obfuscation | Fragmentowanie polecenia i Base64 UTF-16LE (C) |
| `T1053.005` Scheduled Task | Rejestracja zadania `Updater` (C) |
| `T1112` Modify Registry | Zapis wartości `debug` (C) |
| `T1027.011` Fileless Storage | Przechowywanie zakodowanego skryptu w rejestrze (C) |
| `T1105` Ingress Tool Transfer | Udane pobrania FTP `RETR` (C) |
| `T1059.006` Python | Uruchomienie `python.exe dns.py` (C) |
| `T1048.003` Exfiltration Over Unencrypted Non-C2 Protocol | Udane FTP `STOR` i zakodowane zapytania DNS (C dla transmisji, P dla pełnego skutku eksfiltracji) |

Do technik warunkowych zaliczono `T1685` (próba obejścia AMSI), `T1020` (prawdopodobna automatyzacja transferów) i `T1071.001` (próba komunikacji downloadera przez HTTPS). Nie przypisano jako potwierdzonych: `T1204.002` (User Execution konkretnej osoby), `T1555` (pozyskanie haseł z magazynu), `T1113` (Screen Capture) ani lateral movement na podstawie samego pobrania `psexec.exe`. DNS opisano jako kanał przesyłania danych, nie dowiedziony kanał dwustronnego C2.

# Evidence Matrix: twierdzenie → dowód → granica

Tabela obejmuje wybrane wnioski z raportu DFIR. Identyfikatory Evidence odnoszą się do analizy w Splunk BOTSv2; pełny dziennik roboczy pozostaje poza publikacją.

## Poziom pewności

**Wysoka pewność** oznacza bezpośredni zapis zdarzenia, zgodność artefaktu lub wyniku z niezależnym źródłem. **Umiarkowana** oznacza spójną korelację, której nie można w pełni udowodnić na poziomie konkretnego procesu i połączenia. **Nieustalona** oznacza brak materiału potrzebnego do rozstrzygnięcia.

| Ustalenie | Źródło | Pewność i granica |
| --- | --- | --- |
| Cztery wiadomości z identycznym ZIP | SMTP, Evidence 07 i 15 | Wysoka dla wysyłki; nie dla otwarcia załączników |
| Makra VBA oraz wykonanie WMI → PowerShell | Próbka, Sysmon, Evidence 20A, 23F | Wysoka dla kodu i procesów; użytkownicy nieustaleni |
| Połączenie procesu PowerShell do `45.77.65.211` | Sysmon Event ID 1/3, Evidence 24A | Wysoka dla inicjacji TCP; wynik pobrania nieustalony |
| Rejestracja `Updater` i zapis `debug` | Sysmon, WinRegistry, Evidence 24E/24I/24K | Wysoka dla artefaktów; kolejne wykonanie nieustalone |
| 14 udanych `RETR` | FTP, Evidence 25AS | Wysoka dla pobrań, nie dla uruchomienia wszystkich plików |
| 707 udanych `STOR` | FTP, Evidence 25AT | Wysoka dla transferów, nie dla poufności przesłanej treści |
| `frothly_passwords.kdbx` | FTP, Evidence 25AT | Wysoka dla wysłania; zawartość i użycie haseł nieustalone |
| `hildegardsfarm.com` ↔ IP FTP | DNS, Evidence 25AV | Wysoka dla historycznej odpowiedzi DNS |
| Kodowane fragmenty w DNS | DNS, Evidence 25M/25P/25Y | Wysoka dla treści zapytań, nie dla kompletnego pliku |
| 424 identyczne FQDN | DNS, Evidence 25BF | Wysoka dla zgodności nazw w dwóch źródłach |

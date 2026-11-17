# Metodyka i zakres analizy

## Cel i źródła

Punktem wejścia była własna reguła korelacyjna `SOC-DET-001` skonstruowana retrospektywnie dla logów `stream:smtp` w Splunk BOTSv2. Badanie objęło zdarzenia historyczne z 24-26 sierpnia 2017 r. oraz analizę odzyskanej próbki prowadzoną w listopadzie 2026 r.

Wykorzystano logi SMTP, Sysmon, WinRegistry, Security, TCP, FTP, DNS i PAN oraz analizę statyczną `invoice.doc` i dekodowanie fragmentów danych. Weryfikacja hipotez opierała się na korelacji źródeł i odpowiedziach protokołów, nie na samej zbieżności nazw lub znaczników czasu.

## Interpretacja dowodów

- **Wysoka pewność:** bezpośredni zapis zdarzenia, potwierdzony transfer FTP lub zgodność istotnych danych w niezależnym źródle.
- **Umiarkowana pewność:** spójny kontekst zachowania bez dowodu konkretnego związku procesu z operacją sieciową.
- **Nieustalona:** brak danych pozwalających rozstrzygnąć własność infrastruktury, zawartość transferu lub jego ostateczny skutek.

Część zdarzeń w logach Stream ma czas różniący się o około 30-34 sekundy od zbliżonych zdarzeń Sysmon. Nie dopasowano sztucznie czasu ani nie przypisano konkretnego PID do każdej operacji FTP lub DNS.

## Ograniczenia zakresu

To dochodzenie oparte na telemetrii i odzyskanej próbce, nie pełne obrazowanie dysków i pamięci. Analiza nie potwierdza tożsamości operatora infrastruktury ani wykorzystania poświadczeń z `frothly_passwords.kdbx`. W przypadku DNS potwierdzono transmisję kodowanych fragmentów i zgodność 424 FQDN na dwóch odcinkach, a nie odtworzenie całego pliku.

## Odniesienia

Metodykę raportowania oparto na [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), [NIST CSF 2.0](https://doi.org/10.6028/NIST.CSWP.29), [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final) i [MITRE ATT&CK Enterprise](https://attack.mitre.org/).

## Rola AI

AI wspierało przygotowanie i analizę SPL, formułowanie hipotez oraz redakcję dokumentacji. Autor wykonywał i kontrolował zapytania w Splunk, sprawdzał artefakty, weryfikował interpretacje i podejmował decyzje o zakresie dochodzenia.

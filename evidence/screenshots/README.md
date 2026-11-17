# Screenshoty do portfolio

Zestaw zawiera 8 oryginalnych plików: 7 PNG i 1 SVG, wspólnych dla wszystkich raportów. Skopiowano je bez zmiany bajtów. Nazwy z ZIP i sumy SHA-256 zapisano w [manifeście](../SOC_screenshots_manifest.csv).

| Plik | Evidence | Co pokazuje |
| --- | --- | --- |
| `e14-invoice-email.svg` | 14 | Rekonstrukcja wiadomości Invoice |
| `e20a-olevba-macros.png` | 20A | Analiza VBA w olevba |
| `e23f-wmi-powershell.png` | 23F | WMI → PowerShell, trzy hosty |
| `e24a-powershell-network.png` | 24A/24B | Sysmon, połączenie PowerShell |
| `e24i-updater-taskcache.png` | 24I | Zadanie Updater w TaskCache |
| `e25as-ftp-retr.png` | 25AS | 14 żądań RETR; sukcesy zweryfikowano osobno w odpowiedziach FTP |
| `e25at-ftp-stor-kdbx.png` | 25AT | Udany STOR frothly_passwords.kdbx |
| `e25bf-dns-424-fqdn.png` | 25BF | 424 identyczne FQDN |

Wszystkie obrazy są dołączone i wczytują się w lokalnym podglądzie. W PDF zachowano pełne kadry i dodano opisane powiększenia. Wyniki i otwarte kontrole: [raport kontroli](../../PUBLICATION-QA.md). SVG jest rekonstrukcją wiadomości. Sukcesy RETR zweryfikowano osobno z odpowiedzi FTP; licznik 714 na zrzucie STOR obejmuje szersze wyszukiwanie niż 711 operacji FTP.

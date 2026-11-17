# Kontrola pakietu SOC BOTSv2

Stan: 17.11.2026. Pakiet do prywatnego repozytorium `WIIW/SOC_project1_priv`, gałąź `main`.

## Integralność i redakcja

Pobrano 12 oryginalnych załączników Markdown ze strony 06 bez przetwarzania ich treści. Niezmienione kopie zachowano lokalnie poza repozytorium. [Manifest oryginałów](evidence/source-integrity.json) zawiera rozmiary i SHA-256 sprzed redakcji. Liczby „znaków” z Notion nie zawsze odpowiadały rozmiarom w bajtach; nie potraktowano ich jako sum kontrolnych.

Osiem ilustracji z ZIP autora skopiowano bez zmiany bajtów. [Manifest ilustracji](evidence/SOC_screenshots_manifest.csv) łączy nazwy z ZIP z nazwami repozytoryjnymi. Ponownie sprawdzono wszystkie osiem SHA-256.

Zmiany ograniczono do wersji repozytoryjnych:
- Pełny README zastąpił wersję inicjalizacyjną; dodano linki do PDF. We wstępie wyjaśniono cel projektu, czym jest BOTSv2, źródło i licencję danych oraz sposób prowadzenia analizy. Informacje te zastępują osobny plik o materiałach zewnętrznych.
- W trzech raportach dodano informację o retrospektywnej analizie, pomocy AI i statusie zaleceń IR.
- Podpisy DFIR 5 i 6 rozróżniają żądania od sukcesów RETR oraz 714 zdarzeń wyszukiwania od 711 operacji STOR.
- Ujednolicono pauzy w tekście do łącznika. Uaktualniono inwentarz screenshotów.
- Nie zmieniano zatwierdzonych raportów ani załączników w Notion. Cztery pliki pozostały identyczne bajtowo: timeline, IOC, MITRE i evidence matrix. W pliku SPL usunięto jedną zbędną spację na końcu akapitu.

## Wyniki kontroli

| Obszar | Wynik |
| --- | --- |
| Ścieżki | Wszystkie odsyłacze względne i 13 wystąpień obrazów wskazują istniejące pliki; 8 ilustracji unikalnych |
| Lokalny podgląd | Historia, README i trzy raporty otwierają się; wszystkie obrazy wczytane |
| Mermaid | Diagram renderuje 6 węzłów, bez błędów JavaScript. Autor potwierdził poprawny wygląd na GitHubie |
| Ekran 390 px | README mieści się w szerokości; szerokie tabele przewijają się. W L2 długa nazwa źródła Sysmon wymaga poziomego przewinięcia w prostym lokalnym podglądzie |
| PDF | SOC L1: 5 stron; SOC L2: 14 stron; DFIR: 18 stron. A4, osadzone fonty, numeracja, zakładki, odsyłacze; L2/DFIR mają klikalny spis treści |
| PDF na telefonie | Autor potwierdził czytelność |
| Layout | Wszystkie strony wyrenderowano i obejrzano. Brak pustych stron, nakładania tekstu, wyjścia poza marginesy i oderwanych od obrazów podpisów. Nagłówki tabel powtarzają się |
| Dowody | Pełne kadry w tekście i opisane powiększenia z podaniem współrzędnych. Nie rekonstruowano tekstu obrazów |
| Linki zewnętrzne | Otworzono NIST, MITRE, BOTSv2, Szkołę Security, ANY.RUN i tria.ge; tria.ge prowadzi do logowania |
| Dane | Przegląd tekstów, pełnych kadrów i SVG oraz skan wzorców sekretów nie wykazał prywatnych tokenów autora. Brak próbek, pełnych payloadów i surowych eksportów |
| Pochodzenie | Źródło danych i licencję CC0 1.0 podano we [wstępie README](README.md#wstęp) |

Skan wzorców nie gwarantuje wykrycia każdego sekretu. Hasło do ćwiczeniowego ZIP, konta Frothly, adresy i IOC są elementami scenariusza, a nie poświadczeniami autora. Nie odwiedzano historycznych adresów IOC.

## Pozostałe czynności

- Sprawdzić ilustracje i szerokie tabele w widoku GitHuba. Poprawny wygląd diagramu i czytelność PDF na telefonie zostały już potwierdzone przez autora.
- Przeprowadzić test 10 sekund / 2 minuty / 10 minut z niezależnym czytelnikiem. Sprawdzono obecność wyników i nawigacji, scope/IOC oraz granic dowodowych; nie zastępuje to opinii rekrutera lub SOC Lead.
- Publiczne udostępnienie pozostaje osobną decyzją autora. Repozytorium pozostaje prywatne.

Screenshot portfolio można zrobić po otwarciu końcowego README na zalogowanym GitHubie, gdy widoczne są wyniki i w pełni wyrenderowany diagram. Nowe screenshoty dowodowe z laboratorium nie są potrzebne.

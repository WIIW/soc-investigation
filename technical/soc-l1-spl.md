**Status:** prototyp detekcji odtworzony retrospektywnie na bazie BOTSv2, nie wdrożona reguła produkcyjna. Główny ticket SOC L1 jest nadrzędnym dokumentem operacyjnym.

**Źródło:** [Wykaz dowodów](../evidence/evidence-matrix.md). Poniższe zapytania odpowiadają utrwalonym kwerendom z dziennika.

## 1. Cel i logika

Chciałem zbudować prostą regułę, która pomoże mi wychwycić nietypowe rozsyłanie załączników ZIP. Przyjąłem, że warto sprawdzić sytuację, w której ten sam nadawca wysyła plik o tej samej nazwie do co najmniej trzech różnych osób w ciągu 10 minut.

Do analizy wykorzystałem logi poczty z indeksu `botsv2` w Splunku (`sourcetype=stream:smtp`). Z pól `attach_filename{}` i `receiver_email{}` odczytywałem nazwy załączników oraz adresy odbiorców. Dane nadawcy pobierałem z `sender_email` albo `sender`, zależnie od tego, które pole było dostępne.

Nie próbowałem w ten sposób rozpoznawać konkretnego złośliwego programu. Moim celem było znalezienie zachowania, które uzasadniałoby rozpoczęcie triage. Sama zgodność nadawcy, nazwy pliku i liczby odbiorców nie dowodzi phishingu, uruchomienia pliku ani infekcji komputera.

## 2. Wykonana historyczna kwerenda korelacyjna

```text
index="botsv2" sourcetype="stream:smtp" earliest=0 "attach_filename{}"="*.zip"
| eval attachment=mvindex('attach_filename{}',0)
| eval recipient=mvindex('receiver_email{}',0)
| eval sender_address=coalesce(sender_email,sender)
| eval event_time=_time
| where match(attachment,"(?i)\.zip$") AND isnotnull(recipient) AND isnotnull(sender_address)
| bin _time span=10m
| stats min(event_time) AS first_seen max(event_time) AS last_seen dc(recipient) AS recipient_count values(recipient) AS recipients count AS smtp_events BY _time sender_address attachment
| where recipient_count>=3
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S %z"), last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S %z")
| table first_seen last_seen sender_address attachment recipient_count recipients smtp_events
| sort first_seen
```

**Wynik:** moje zapytanie wykryło wysyłkę `invoice.zip` od `jsmith@urinalysis.com` do czterech różnych odbiorców. Znalazłem cztery rekordy wiadomości SMTP z 24.08.2017, z okresu 03:27\:14-03\:27:33 UTC. Szczegóły zapisałem jako Evidence 07.

## 3. Ustalenie logicznego momentu przekroczenia progu

```text
index="botsv2" sourcetype="stream:smtp" earliest=0 "invoice.zip"
| eval attachment=mvindex('attach_filename{}',0)
| eval recipient=mvindex('receiver_email{}',0)
| eval sender_address=coalesce(sender_email,sender)
| where attachment="invoice.zip" AND sender_address="jsmith@urinalysis.com"
| where _time>=strptime("2017-08-24 03:27:00 +0000","%Y-%m-%d %H:%M:%S %z")
    AND _time<strptime("2017-08-24 03:28:00 +0000","%Y-%m-%d %H:%M:%S %z")
| sort 0 _time
| streamstats dc(recipient) AS unique_recipients
| eval detection_trigger=if(unique_recipients=3,"THRESHOLD REACHED","")
| eval event_utc=strftime(_time,"%Y-%m-%d %H:%M:%S %z")
| table event_utc sender_address recipient subject attachment unique_recipients detection_trigger
```

| Zdarzenie | Odbiorca | Czas UTC | Liczba unikalnych odbiorców |
| --- | --- | --- | --- |
| 1 | `abungstein@froth.ly` | 03:27:14.323 | 1 |
| 2 | `klagerfield@froth.ly` | 03:27:24.557 | 2 |
| 3 | `btun@froth.ly` | **03:27:29.837** | **3, warunek spełniony** |
| 4 | `fyodor@froth.ly` | 03:27:33.239 | 4 |

**Uwaga:** godzinę 03:27:29.837 UTC wyznaczyłem na podstawie kolejności historycznych zdarzeń. To moment, w którym pojawił się trzeci odbiorca, a nie potwierdzona godzina wygenerowania alertu w prawdziwym SOC w 2017 r. Nie wiem, kiedy takie logi trafiłyby wtedy do systemu ani kiedy analityk otrzymałby zgłoszenie. Zapytanie wykonałem podczas pracy nad projektem w listopadzie 2026 r.

## 4. Co reguła potrafi, czego może nie zauważyć i co chciałbym jeszcze poprawić?

**W moim projekcie reguła spełniła swoje zadanie.** Wyszukała cztery wiadomości wysłane w krótkim czasie przez tego samego nadawcę, z załącznikiem ZIP o tej samej nazwie. Dzięki temu miałem konkretny punkt wyjścia do analizy phishingu.

Nie uważam jednak, że obecna wersja nadaje się już do codziennego używania w SOC. Napisałem ją po to, żeby sprawdzić pomysł na historycznych logach. Po wykonaniu testów widzę kilka rzeczy, które należałoby jeszcze poprawić.

**1. Reguła może przeoczyć wiadomości wysłane na granicy dwóch przedziałów czasu.**

Moje pierwsze zapytanie dzieli logi na osobne, 10-minutowe przedziały. Załóżmy, że dwie podejrzane wiadomości zostały wysłane o 12:09, a trzecia o 12:10. Choć dzieli je tylko chwila, Splunk może przypisać je do dwóch różnych grup. W żadnej nie znajdzie wtedy wymaganych trzech odbiorców.

W kolejnej wersji zmieniłbym ten mechanizm tak, aby sprawdzać dowolne 10 minut, a nie tylko z góry wyznaczone przedziały.

**2. Sprawdzany jest tylko pierwszy załącznik i pierwszy odbiorca.**

W testowanym SPL uprościłem analizę. Jeśli log zawiera listę kilku załączników lub odbiorców, pobieram z niej tylko pierwszą pozycję. To wystarczyło dla badanego przypadku, ale przy innej wiadomości mógłbym przeoczyć istotne dane.

Przed wdrożeniem reguły konieczne byłoby uwzględnienie wszystkich załączników i adresatów. Sprawdziłbym też, czy to samo zdarzenie nie zostało zapisane kilka razy i nie zawyża wyniku.

**3. Reguła może zgłosić całkiem normalną korespondencję.**

W firmie zdarzają się przecież sytuacje, w których jeden plik ZIP trafia do kilku pracowników. Mogą to być materiały szkoleniowe, raporty czy dokumenty do wspólnego projektu. Moja reguła mogłaby zgłosić taki przypadek jako podejrzany, choć nie doszło do ataku. To tak zwany ***false positive***, czyli fałszywy alarm.

Możliwa jest również sytuacja odwrotna. Jeśli rzeczywista kampania phishingowa nie spełni przyjętych przeze mnie warunków, nie zobaczę jej w wynikach. To ***false negative***, czyli przeoczone zagrożenie.

Dlatego przed użyciem reguły w prawdziwym SOC sprawdziłbym ją także na legalnych wiadomościach i różnych wariantach podejrzanych wysyłek (warunki brzegowe). Chciałbym wiedzieć, kiedy pomaga analitykowi, a kiedy tylko dokłada mu pracy.

**4. Konieczne przygotowanie do automatycznej pracy.**

W tym projekcie uruchamiałem zapytania ręcznie w Splunku. W działającym SOC reguła powinna wykonywać się automatycznie, na przykład raz na minutę. Musiałbym też uwzględnić opóźnienia w dostarczaniu logów, aby nie przeoczyć wiadomości tylko dlatego, że ich zapis pojawił się w systemie nieco później.

Zależałoby mi również na tym, żeby jedna kampania nie generowała wielu prawie identycznych powiadomień. Analityk powinien od razu zobaczyć, kto wysłał wiadomości, do kogo, z jakim załącznikiem i dlaczego system uznał to za podejrzane.

**5. Na tym etapie jest to nadal prototyp.**


Potwierdziłem, że moje zapytanie znajduje odpowiednie zdarzenia w BOTSv2. Ustaliłem również, że warunek trzech różnych odbiorców został spełniony 24 sierpnia 2017 r. o 03:27:29.837 UTC.


**Wniosek:** jako punkt startowy dochodzenia reguła sprawdziła się dobrze. Gdyby chcieć ją wdrożyć  w rzeczywistym środowisku, wymagałaby jeszcze poprawy sposobu liczenia wiadomości i czasu, sprawdzenia możliwych fałszywych alarmów oraz skonfigurowania automatycznego uruchamiania i przekazywania zgłoszeń.

## 5. Dowody źródłowe

- Evidence 07: trafienie reguły i agregacja czterech zdarzeń.
- Evidence 08: kolejność czterech wiadomości i trzeci odbiorca osiągający próg.
- Evidence 15: cztery zgodne metadane załącznika.
- Evidence Journal, §15-16: konieczne prace nad wersją produkcyjną i ograniczenia symulowanego czasu alertu.

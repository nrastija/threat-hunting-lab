# 3. Organizacija tima i uloge

Laboratorijsko okruženje i proces lova na prijetnje zahtijevaju koordinirani rad više stručnjaka. Tim je strukturiran kako bi obuhvatio sve ključne uloge od implementacije sustava do analize napada i izvještavanja.

## 3.1. Struktura tima
Tim se sastoji od četiri glavne uloge: Data Engineer, Threat Hunter, Attack Simulation Engineer i Analyst/Reporter. Svaka uloga ima jasno definirane odgovornosti, a suradnja između članova omogućuje efikasan rad i pravilnu interpretaciju prikupljene telemetrije.

1. **Data Engineer (Niko Rastija):** Odgovoran je za projektiranje i postavljanje laboratorijske infrastrukture. Njegov rad obuhvaća konfiguraciju virtualnih strojeva (Ubuntu, Windows), implementaciju SIEM sustava (Wazuh), mrežnih senzora (Suricata) i honeypota (Cowrie). Ključni zadatak bio je osigurati stabilan protok telemetrije s endpointa prema centralnom poslužitelju.
2. **Threat Hunter (Petra Skoko):** Fokusira se na analizu prikupljenih podataka u svrhu otkrivanja anomalija i indikatora kompromitacije (IoC). Koristeći KQL upite unutar Wazuh Dashboarda i analizirajući Sysmon logove, Petra je zadužena za identifikaciju sumnjivih procesa i testiranje detekcijskih pravila temeljenih na prikupljenoj telemetriji.
3. **Attack Simulation Engineer (Nensi Vugrinec):** Odgovorna je za planiranje i izvođenje simulacija napada. Kroz korištenje alata poput Kali Linuxa, Nensi generira realistične napadačke scenarije (poput SSH brute-force napada ili manipulacije memorijom procesa) kako bi testirala učinkovitost postavljenih sigurnosnih kontrola.
4. **Analyst/Reporter (Mirta Vuković):** Mirta sintetizira rezultate simulacija i procesa lova u strukturirane izvještaje. Njezina uloga uključuje dokumentiranje pronađenih incidenata, vizualizaciju podataka kroz dashboarde te interpretaciju tehničkih nalaza na način koji omogućuje donošenje konkretnih sigurnosnih preporuka.

---

# 4. Implementacija i arhitektura testnog okruženja

Ovo poglavlje detaljno opisuje proces izgradnje laboratorijskog okruženja, od mrežne topologije do instalacije specijaliziranih alata za nadzor i telemetriju.

## 4.1. Pregled laboratorijskog okruženja (Mock Enterprise)
Laboratorij je dizajniran kao izolirano korporativno okruženje unutar virtualizacijske platforme (Oracle VM VirtualBox). Sastoji se od tri ključna segmenta: napadačke stanice (Kali Linux), endpoint žrtve (Windows 10) i centralnog sigurnosnog poslužitelja (Ubuntu Server s Wazuh SIEM sustavom). Takva arhitektura omogućuje simulaciju realističnih napadačkih scenarija, praćenje aktivnosti napadača te analizu učinkovitosti sigurnosnih kontrola u kontroliranom okruženju [1].
## 4.2. Topologija mreže i hardverski preduvjeti

Svi virtualni strojevi u laboratorijskom okruženju povezani su unutar iste podmreže kako bi se osigurala nesmetana komunikacija i centralizirano prikupljanje logova. Takva konfiguracija omogućuje simulaciju realističnih napadačkih scenarija unutar izolirane mreže, bez utjecaja na vanjske sustave.

Dijagram mrežne arhitekture (Slika 2) prikazuje logičku strukturu laboratorijskog okruženja.

* **Ubuntu SIEM/IDS poslužitelj:** Zauzima centralnu poziciju i pasivno prima mrežni promet od endpointa i honeypota, istovremeno pohranjujući i analizirajući logove s krajnjih točaka.
* **Windows endpoint:** Konfiguriran kao tipična žrtva, generira standardnu i naprednu telemetriju (Windows Event Log, Sysmon, login/logout događaje) koja se prosljeđuje u SIEM sustav.
* **Napadačka stanica (Kali Linux):** Smještena tako da može simulirati i vanjske prijetnje (putem SSH honeypota) i unutarnje napade na endpoint, omogućujući analizu širokog spektra napadačkih vektora [5].
* **Honeypot (Cowrie SSH):** Konfiguriran da emulira ranjivi SSH servis. Svi pokušaji prijave bilježe se u log datoteci koja je integrirana u SIEM, čime se omogućuje praćenje i analiza napada.

**Ovakva mrežna topologija omogućuje:**
* Centraliziranu analizu sigurnosnih događaja kroz Wazuh Dashboard.
* Praćenje i korelaciju podataka s mrežne i endpoint razine.
* Testiranje detekcijskih pravila za IDS/IPS sustave.
* Evaluaciju učinkovitosti sigurnosnih kontrola u kontroliranom i izoliranom laboratorijskom okruženju.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Dijagram.png?raw=true" alt="Slika 2. Dijagram mrežne arhitekture" width="500">
  <br>
  <b>Slika 2. Dijagram mrežne arhitekture laboratorijskog okruženja</b>
</p>


## 4.3. Implementacija sigurnosnih i nadzornih alata
Ovo poglavlje opisuje implementaciju ključnih sigurnosnih i nadzornih alata korištenih u laboratorijskom okruženju. Cilj implementacije bio je uspostaviti centralizirani sustav za prikupljanje, analizu i korelaciju sigurnosnih događaja s endpoint i mrežnih razina, uz mogućnost detekcije i analize napadačkih aktivnosti u kontroliranom okruženju.


Automatizirana instalacija SIEM sustava provedena je putem skripte koja obuhvaća pripremu sustava, instalaciju svih Wazuh komponenti, konfiguraciju Suricata IDS-a s ažuriranim pravilima te verifikaciju ispravnosti konfiguracijskih datoteka. Ova procedura osigurava ponovljivost procesa i minimizira ljudske pogreške.

### 4.3.1. Postavljanje SIEM i IDS okruženja
Uspostava SIEM i IDS okruženja temeljni je korak u izgradnji laboratorijske infrastrukture. Cilj je kreirati centralizirani sustav za prikupljanje i analizu podataka koji analitičarima omogućuje potpuna uvid u mrežne i sistemske aktivnosti. Integracijom ovih alata osigurava se platforma za pravovremenu detekciju anomalija i testiranje hipoteza lova na prijetnje [4].

#### 4.3.1.1.	Korištene tehnologije
Za implementaciju centraliziranog sustava za prikupljanje i analizu sigurnosnih događaja korištene su sljedeće tehnologije:

- **Ubuntu Server 22.04 LTS** – temeljni operacijski sustav SIEM poslužitelja  
- **Wazuh SIEM** – sustav za prikupljanje, analizu i korelaciju sigurnosnih događaja (Manager, Indexer i Dashboard)  
- **Suricata IDS** – sustav za detekciju sumnjivog mrežnog prometa  
- **Bash skripta** – automatizacija instalacije i inicijalne konfiguracije sigurnosnog okruženja  

Ovakva kombinacija alata omogućuje centralizirani nadzor nad endpoint i mrežnim događajima te njihovu korelaciju unutar jednog sučelja.

#### 4.3.1.2.	Postupak instalacije SIEM sustava
Pokretanje virtualnog stroja za SIEM sustav provedeno je korištenjem alata Oracle VM VirtualBox ili VMware Workstation. Nakon pokretanja Ubuntu Server sustava, identificirana je njegova IP adresa pomoću naredbe: ip a

Korištena je IPv4 adresa iz privatnog mrežnog raspona 192.168.XX.XX/24, koji omogućuje izolirano laboratorijsko okruženje.

Sa primarnog Windows računala uspostavljena je SSH veza prema SIEM poslužitelju. Preduvjet za ovaj korak je instaliran SSH Client na Windows 10/11 sustavu te ponovno pokretanje računala.

Povezivanje je izvršeno putem PowerShella s administratorskim privilegijama: ssh user@SIEM_IP

Nakon uspješne prijave, kreirana je instalacijska skripta install_siem.sh (vidi Prilog 1) pomoću tekstualnog uređivača: nano install_siem.sh

U skriptu je zalijepljen sadržaj preuzet iz pripadajućeg GitHub repozitorija, koji automatizira: instalaciju Wazuh Managera, Indexera i Dashboarda, konfiguraciju servisa, inicijalno pokretanje sustava, generiranje administratorske lozinke.

Instalacija SIEM sustava pokrenuta je naredbom: sudo bash install_siem.sh

Tijekom instalacije, skripta također konfigurira osnovne sigurnosne postavke Wazuh Dashboarda, uključujući generiranje self-signed certifikata za HTTPS promet i sigurno upravljanje administratorskim lozinkama. Ove postavke omogućuju siguran pristup Dashboardu unutar laboratorijske mreže. Po završetku instalacije, Wazuh Dashboard postaje dostupan putem web preglednika na adresi: https://SIEM_IP

Tijekom instalacije, administratorska lozinka generira se automatski te se ispisuje u konzoli. Primjer ispisa: INFO: The password for user admin is xxxxxxxxxxxx

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Zavr%C5%A1niIspisAutomatiziraneInstalacijskeSkripte.png?raw=true" alt="Završni ispis automatizirane instalacijske skripte" width="500">
  <br>
  <b>Slika 3. Završni ispis automatizirane instalacijske skripte</b>
</p>

#### 4.3.1.3. Pristup Wazuh Dashboardu

Pristup **Wazuh Dashboardu** ostvaren je putem web sučelja:

- **URL:** `https://SIEM_IP`  
- **Korisničko ime:** `admin`  
- **Lozinka:** generirana tijekom izvršavanja skripte `install_siem.sh`  

Dashboard omogućuje centralizirani pregled agenata, sigurnosnih događaja, upozorenja te integriranih alata poput IDS-a i honeypota.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/WazuhDashboardLoginSu%C4%8Delje.png?raw=true" alt="Wazuh Dashboard login sučelje" width="500">
  <br>
  <b>Slika 4. Wazuh Dashboard login sučelje pristupljeno putem HTTPS protokola</b>
</p>

### 4.3.2. Endpoint sustav - Windows virtualni stroj
Implementacija Windows endpointa ključna je za testiranje naprednih tehnika napada na klijentske sustave. Kroz integraciju Wazuh agenta, ovaj stroj prestaje biti izolirana jedinica i postaje aktivan izvor telemetrije, omogućujući SIEM sustavu dubinski uvid u sigurnosno stanje i operativne promjene na razini operacijskog sustava žrtve.

#### 4.3.2.1.	Priprema Windows virtualnog stroja
Windows 10 Pro virtualni stroj konfiguriran je kao endpoint žrtva u laboratorijskom okruženju. Prije instalacije sigurnosnih agenata, provedena je provjera mrežne povezanosti prema SIEM poslužitelju pomoću ICMP protokola: ping SIEM_IP

Uspješna komunikacija potvrđena je primanjem ICMP odgovora bez gubitka paketa, čime je osigurana osnovna mrežna dostupnost između endpointa i SIEM sustava.

#### 4.3.2.2. Instalacija Wazuh agenta
Uspješno povezivanje Windows endpointa sa središnjim SIEM sustavom zahtijeva ispunjenje određenih preduvjeta, prvenstveno posjedovanje administratorskih ovlasti na lokalnom stroju te osiguranu mrežnu vidljivost prema IP adresi menadžera. Proces započinje unutar Wazuh Dashboarda, gdje se putem interaktivnog sučelja u sekciji za postavljanje novih agenata definira tip instalacijskog paketa (Windows MSI), IP adresa poslužitelja (192.168.54.135) te jedinstveno ime agenta radi lakše identifikacije.

Nakon konfiguracije parametara, sustav generira specifičnu PowerShell naredbu koju je potrebno izvršiti na Windows virtualnom stroju. Ova naredba automatski preuzima MSI instalacijski paket s udaljenog repozitorija i vrši tihu instalaciju agenta u pozadini. Po završetku instalacije, agent se aktivira kao sistemski servis, čime se uspostavlja kriptirana veza za prijenos telemetrije. Finalna potvrda uspješnosti procesa vidljiva je u "Agent Summary" panelu dashboarda, gdje status agenta prelazi u "Active". Suricata IDS kontinuirano prati mrežni promet s endpointa, a Wazuh agent prikuplja standardne Windows Event Logove i druge sigurnosne podatke. Time se osigurava centralizirana vidljivost nad operativnim i sigurnosnim događajima krajnjih točaka. U ovoj fazi, sustav počinje prikupljati standardne podatke poput Windows Event Logova, informacija o prijavama i odjavama korisnika, sistemskih događaja te vršiti osnovne sigurnosne baseline provjere.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/CentralniPregledWazuhDashboarda.png?raw=true" alt="Slika 5. Potvrda aktivnog agenta" width="500">
  <br>
  <b>Slika 5. Centralni pregled Wazuh Dashboarda s potvrdom jednog aktivnog agenta</b>
</p>

### 4.3.3. Endpoint telemetrija - Sysmon
Za prikupljanje napredne endpoint telemetrije implementiran je Microsoft Sysmon (System Monitor), koji proširuje standardne Windows sigurnosne logove i omogućuje detaljan uvid u aktivnosti operacijskog sustava. Sysmon bilježi ključne događaje poput kreiranja novih procesa (Event ID 1), mrežnih konekcija iniciranih od strane procesa (Event ID 3) te pristupa memoriji procesa (Event ID 10), što je ključno za detekciju sofisticiranih napadačkih alata i manipulacija u memoriji sustava [4]. Instalacija je izvedena uz korištenje službenog paketa Sysmon i unaprijed definirane SwiftOnSecurity konfiguracijske datoteke, optimizirane za sigurnosni nadzor i prihvatljivu količinu generiranih logova. Tijekom instalacije Sysmon je registriran kao sistemski servis, omogućujući kontinuirano praćenje relevantnih događaja u stvarnom vremenu. Svi generirani događaji integrirani su u Windows Event Log, odakle ih Wazuh agent prikuplja i prosljeđuje u centralni SIEM sustav, čime se osigurava centralizirano prikupljanje, korelacija i analiza napredne endpoint telemetrije unutar laboratorijskog okruženja.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Provjera%20statusa%20Sysmon64%20servisa%20na%20Windows%2010%20Endpointu%20putem%20PowerShell%20konzole.png?raw=true" alt="Provjera statusa Sysmon64 servisa" width="500">
  <br>
  <b>Slika 6. Provjera statusa Sysmon64 servisa na Windows 10 Endpointu putem PowerShell konzole</b>
</p>

## 4.3.4. Honeypot

Kao zadnja linija obrambene telemetrije u laboratorijskom okruženju postavljen je **Cowrie SSH Honeypot** na SIEM poslužitelju. Njegova uloga je prikupljanje detaljnih informacija o pokušajima neovlaštenog pristupa i napadačkim tehnikama bez izlaganja stvarnih servisa riziku.

- Proces instalacije: 
Cowrie je postavljen unutar izoliranog Python virtualnog okruženja (python3 -m venv cowrie-env) kako bi se osigurala stabilnost sustava

- Funkcionalnost: Svi pokušaji brute-force napada, korištena korisnička imena i lozinke bilježeni su u log datoteci cowrie.json, koja je integrirana u Wazuh SIEM sustav. Na taj način, honeypot omogućuje centraliziranu analizu napadačkih aktivnosti i testiranje detekcijskih pravila unutar laboratorijskog okruženja [5].

- Verifikacija: Ispravnost rada potvrđena je naredbom cowrie status, koja je vratila aktivan Process ID (PID), signalizirajući da je sustav spreman za prikupljanje podataka o napadima koje će biti simulirani.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Potvrda%20uspje%C5%A1nog%20pokretanja%20Cowrie%20SSH%20honeypota.png?raw=true" alt="Potvrda uspješnog pokretanja Cowrie SSH honeypota" width="500">
  <br>
  <b>Slika 7. Potvrda uspješnog pokretanja Cowrie SSH honeypota</b>
</p>

---

# 5. Threat Hunting Plan
Ovo poglavlje definira strateški okvir za proaktivno traženje prijetnji unutar laboratorijskog okruženja. Plan povezuje simulirane napade s metodama detekcije, koristeći prikupljenu telemetriju za potvrdu sigurnosnih hipoteza.

## 5.1. Metodologija threat huntinga
Metodologija lova na prijetnje u ovom projektu temelji se na **„Assume Breach”** mentalitetu. Proces prati strukturirani i ponovljivi ciklus:

1. **Razvoj hipoteze**  
   Na temelju **MITRE ATT&CK** okvira pretpostavlja se postojanje specifične napadačke tehnike.

2. **Simulacija napada**  
   Izvođenje kontroliranih napada korištenjem alata kao što su **Hydra**, **Atomic Red Team** i **PowerShell skripte**.

3. **Prikupljanje podataka**  
   Analiza telemetrije prikupljene putem **Wazuh agenta**, **Sysmon-a** i **Cowrie SSH honeypota**.

4. **Analiza i verifikacija**  
   Korištenje specifičnih upita (**KQL**) i prilagođenih detekcijskih pravila za potvrdu uspješnosti detekcije.

## 5.2. Izvori podataka
Za uspješan lov na prijetnje integrirani su različiti izvori podataka kako bi se osigurala vidljivost na svim razinama:
- Honeypot logovi (Cowrie): Izvor podataka za mrežne napade i pokušaje neovlaštenog pristupa (JSON format)
- Endpoint telemetrija (Sysmon): Pruža detaljan uvid u događaje na Windows sustavu (Event ID 1, 3, 10, 22)
- Wazuh Alerts: Centralno mjesto za korelaciju svih događaja i aktivaciju alarmnih pravila


## 5.3. Hipoteze lova i MITRE ATT&CK mapiranje
Lovačke aktivnosti pokreću se na temelju triju hipoteza koje pretpostavljaju prisutnost specifičnih tehnika napada. Lovačke aktivnosti pokreću se na temelju triju hipoteza koje pretpostavljaju prisutnost specifičnih tehnika napada. Kako bi se osigurao strukturiran pristup, odabrane tehnike su vizualizirane pomoću MITRE ATT&CK Navigatora, što omogućuje jasan pregled pokrivenosti napadačkog lanca (Slika 8).

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/dev/docs/images/Mapiranje%20testiranih%20tehnika%20unutar%20MITRE%20ATT%26CK%20Navigatora.png?raw=true" alt="Slika 8. MITRE Navigator" width="500">
  <br>
  <b>Slika 8. Mapiranje testiranih tehnika unutar MITRE ATT&CK Navigatora</b>
</p>

### 5.3.1. Hipoteza 1: SSH Brute-Force (T1110.001)
- Pretpostavka: Napadač pokušava dobiti početni pristup _(eng. Initial Access)_ sustavu automatiziranim pogađanjem lozinki na SSH servisu. Tijekom izvođenja brute force napada s Kali Linux sustava na Windows uređaj koji je povezan sa Wazuh platformom očekuje se da će se pojaviti zapisi o više uzastopnih prijava u sustav u kratkom vremenskom rasponu. Takvo ponašanje može upućivati na kompromitaciju računala brute force napadom.
- MITRE ATT&CK Tehnika: T1110.001 - Password Guessing
- Strategija detekcije: Strategija otkrivanja se temelji na pravilu/upitu koji se aktivira i koji generira zapis kada se unutar određenog vremenskog okvira zabilježi više uspješnih prijava s iste lokacije


### 5.3.2. Hipoteza 2: Krađa vjerodajnica iz LSASS memorije (T1003.001)
- Pretpostavka: Napadač koji je već kompromitirao radnu stanicu pokušava izvući hashirane lozinke ili Kerberos tickete iz memorije procesa lsass.exe. Prilikom izvođenja simuliranog napada nad LSASS procesom na Windows endpointu korištenjem „Atomic Red Team“ alata očekuje se generiranje zapisa koji upućuju na događaje koji su povezani sa pristupom osjetljivoj memoriji od strane procesa.
- MITRE ATT&CK Tehnika: T1003.001 - LSASS Memory
- Strategija detekcije: Za otkrivanje napada bilo je potrebo prikupiti i analizirati Sysmon zapise koji su se generirali prilikom pristupa LSASS procesu. Nakon omogućavanja Sysmon zapisivanja unutar Wazuh agenta generirani događaji se analiziraju kako bi se identificirali procesi koji pokušavaju pristupiti memoriji LSASS-a. Analiza pristupa memoriji procesa ključna je jer napadači često koriste legitimne funkcije sustava za krađu vjerodajnica [3].


### 5.3.3. Hipoteza 3: Eksfiltracija podataka putem DNS-a (T1048.003)
- Pretpostavka: Napadač koristi DNS upite kao prikriveni kanal za iznošenje osjetljivih podataka iz mreže kako bi izbjegao klasične vatrozide. Izvođenjem simuliranog napada eksfiltracije podataka putem DNS protokola s Windows endpointa očekuje se generiranje zapisa koji sadrže neuobičajeno duge nazive domena.
- MITRE ATT&CK Tehnika: T1048.003 - Exfiltration Over DNS
- Strategija detekcije: Za otkrivanje napada bilo je potrebno prikupiti Sysmon DNS query zapise (Event ID 22) koji prikazuju koje domene procesi na sustavu pokušavaju dohvatiti putem DNS upita. Analizom zapisa potrebno je identificirati DNS upite koji završavaju na specifičnu testnu domenu što bi moglo upućivati na pokušaj eksfiltracije podataka putem DNS protokola

---

# 6. Simulacija napada (Attack Simulation)
Simulacija napada predstavlja praktičnu realizaciju Threat hunting plana opisanog u prethodnom poglavlju. Cilj simulacija bio je generirati realistične sigurnosne događaje koji odgovaraju odabranim MITRE ATT&CK tehnikama te provjeriti vidljivost i detekcijske sposobnosti implementiranog SIEM/IDS okruženja.

Napadi su izvođeni u kontroliranom laboratorijskom okruženju korištenjem virtualnih strojeva, pri čemu nije došlo do stvarne kompromitacije sustava. Svaka simulacija osmišljena je tako da reproducira tipično ponašanje napadača u različitim fazama napadačkog lanca - od inicijalnog pristupa do eksfiltracije podataka. Simulacija omogućuje lovcu da testira detekcijske mehanizme u sigurnom okruženju prije pojave stvarnog incidenta [5].

### 6.1. Ciljevi simulacije napada
Glavni ciljevi simulacija napada bili su:
- generirati realističnu telemetriju na mrežnoj i endpoint razini
- validirati hipoteze definirane u Threat Hunting Planu
- testirati mogućnosti detekcije i korelacije događaja unutar Wazuh SIEM sustava
- procijeniti učinkovitost integriranih alata (Cowrie, Sysmon, Suricata)

Simulacije su provedene s naglaskom na edukativni i analitički aspekt, a ne na postizanje stvarne štete.

### 6.2. Korišteni alati za simulaciju
Za izvođenje simuliranih napada korišteni su sljedeći alati i tehnologije:
- Hydra - alat za izvođenje automatiziranih brute-force napada nad servisima
- Cowrie SSH Honeypot - emulacija ranjivog SSH servisa za privlačenje i bilježenje napadačkih aktivnosti
- Atomic Red Team - framework za sigurnu simulaciju MITRE ATT&CK tehnika
- PowerShell - izvođenje skripti i simulacija na Windows endpoint sustavu
- tcpdump - praćenje i analiza mrežnog DNS prometa
- Wazuh SIEM - centralna platforma za prikupljanje, korelaciju i vizualizaciju sigurnosnih događaja

Kombinacija navedenih alata omogućila je pokrivanje više faza napadačkog ciklusa.

### 6.3. Scenarij 1: Brute-force napad na SSH servis
U prvom scenariju simuliran je brute-force napad na SSH servis s ciljem dobivanja početnog pristupa sustavu _(eng. Initial Access)_. Napad je izveden s Kali Linux virtualnog stroja prema Cowrie SSH honeypotu, koji se nalazio na Ubuntu SIEM poslužitelju.

Cowrie honeypot emulira ranjivi SSH servis i bilježi sve pokušaje autentikacije, uključujući korisnička imena, lozinke, izvorišne IP adrese te aktivnosti nakon uspješne prijave. Time je omogućeno prikupljanje detaljnih zapisa o ponašanju napadača bez ugrožavanja stvarnog sustava.

Automatizirani napad generirao je velik broj autentikacijskih pokušaja u kratkom vremenskom razdoblju, čime su stvoreni uvjeti za testiranje korelacijske logike unutar SIEM sustava.

**MITRE ATT&CK tehnika: T1110.001** - Password Guessing

Ova tehnika pripada taktici _Credential Access_ i često se koristi kao metoda inicijalnog kompromitiranja sustava s izloženim servisima.

### 6.4. Scenarij 2: Krađa vjerodajnica (Credential Dumping)
Drugi scenarij simulirao je napad krađe vjerodajnica s Windows endpoint sustava putem pristupa memoriji procesa lsass.exe. Ovaj scenarij pretpostavlja da je napadač već ostvario lokalni pristup sustavu te pokušava eskalirati napad izvlačenjem osjetljivih podataka.

Simulacija je provedena korištenjem alata Atomic Red Team, koji omogućuje sigurno izvođenje napadačkih tehnika bez stvarne krađe podataka. Napad je generirao događaje povezane s pokušajem pristupa memoriji LSASS procesa, koji su zatim prikupljeni putem Sysmon telemetrije i proslijeđeni u Wazuh SIEM.

**MITRE ATT&CK tehnika: T1003.001** – LSASS Memory

Ova tehnika pripada taktici_ Credential Access_ i predstavlja jednu od najčešćih metoda krađe vjerodajnica u Windows okruženjima.

### 6.5. Scenarij 3: Eksfiltracija podataka putem DNS protokola
Treći scenarij simulirao je eksfiltraciju podataka korištenjem DNS protokola kao prikrivenog komunikacijskog kanala. Napad je izveden s Windows endpoint sustava, dok je Kali Linux poslužio kao DNS listener.

Osjetljivi podatak kodiran je u Base64 format te fragmentiran i poslan kroz niz DNS upita. Ovakav oblik prometa često prolazi nezapaženo u mrežama jer DNS predstavlja legitimnu i nužnu uslugu.

Tijekom simulacije zabilježen je neuobičajen obrazac DNS prometa, uključujući dugačke nazive domena i visoku frekvenciju upita, što predstavlja tipične indikatore eksfiltracije podataka.

**MITRE ATT&CK tehnika: T1048.003** – Exfiltration Over DNS

Ova tehnika pripada taktici_ Exfiltration_ i koristi se za zaobilaženje mrežnih sigurnosnih kontrola.

Rezultati svih simulacija detaljno su analizirani i dokumentirani u Dnevniku lova (poglavlje 7), gdje su prikazani konkretni zapisi, upiti, pravila i analitički zaključci za svaki scenarij.




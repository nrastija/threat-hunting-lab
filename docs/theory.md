# 1. Uvod

Porast složenosti i učestalosti kibernetičkih napada doveo je do situacije u kojoj tradicionalni sigurnosni mehanizmi, poput antivirusnih rješenja i sustava detekcije temeljenih na potpisima, više nisu dovoljni za učinkovitu zaštitu informacijskih sustava. Moderni napadači sve češće koriste legitimne alate i tehnike kako bi prikrili svoje aktivnosti, čime uspijevaju zaobići automatizirane obrambene mehanizme i ostati neprimijećeni dulje vrijeme.

U tom kontekstu, lov na prijetnje (Threat Hunting) pojavljuje se kao proaktivan sigurnosni pristup koji nadopunjuje postojeće obrambene sustave. Umjesto oslanjanja isključivo na alarme, threat hunting se temelji na aktivnoj ulozi analitičara koji, koristeći dostupnu telemetriju, sustavno traži anomalije i obrasce ponašanja koji mogu upućivati na prisutnost napadača. Ovakav pristup značajno smanjuje vrijeme zadržavanja napadača u sustavu (eng. dwell time) te omogućuje pravovremenu reakciju prije nastanka veće štete.

Cilj ovog projektnog rada je istražiti i demonstrirati primjenu threat huntinga u kontroliranom laboratorijskom okruženju. Rad obuhvaća izgradnju sigurnosne arhitekture, definiranje lovačkih hipoteza temeljenih na MITRE ATT&CK okviru, provedbu simulacija napada te analizu učinkovitosti detekcije. Poseban naglasak stavljen je na dokumentiranje analitičkog procesa i evaluaciju sigurnosnih rizika iz perspektive analitičara.

Rad je strukturiran tako da u teorijskom dijelu daje pregled osnovnih koncepata threat huntinga, dok praktični dio prikazuje implementaciju alata, simulaciju napada i analizu dobivenih rezultata. Zaključno, rad nastoji pokazati kako threat hunting predstavlja ključan element moderne strategije kibernetičke sigurnosti.

# 2. Teorijska osnova

Sljedeća poglavlja donose pregled ključnih teorijskih koncepata na kojima se temelji implementacija i analiza u praktičnom dijelu ovog projekta.

## 2.1. Što je threat hunting?

Lov na prijetnje (eng. Threat hunting) je strukturirani, ponavljajući proces koji predstavlja proaktivnu sigurnosnu strategiju koja se temelji na pretpostavci da su napadači već prisutni u mreži, ali su uspjeli izbjeći detekciju automatiziranih sustava [1]. Prema SANS institutu [1], lov na prijetnje nije samo tehnološki proces, već disciplina vođena analitičarom koja cilja na pronalaženje naprednih postojanih prijetnji (APT) koje vatrozidi i antivirusni programi ne prepoznaju [2]. Za razliku od tradicionalnog upravljanja incidentima koje se oslanja na reaktivno odgovaranje na alarme, lov na prijetnje predstavlja proaktivni, iterativni proces u kojem analitičari, prema navodima Huntpedije [2], ne čekaju upozorenja sustava, već aktivno traže anomalije koristeći duboko poznavanje TTP-ova (Tactics, Techniques, and Procedures) napadača. Lov na prijetnje započinje postavljanjem hipoteze temeljene na obavještajnim podacima o prijetnjama, prethodnim incidentima ili poznatim taktikama i tehnikama napadača. Analitičar zatim koristi dostupne podatke kako bi potvrdio ili odbacio postavljenu hipotezu [2].

Ključna karakteristika lova na prijetnje je njegovo oslanjanje na razumijevanje ponašanja napadača, a ne samo na prepoznavanje zlonamjernog koda. Napadači često koriste legitimne alate i tehnike administracije sustava kako bi prikrili svoje aktivnosti, što dodatno otežava njihovo otkrivanje. Napadači sve češće koriste legitimne sistemske alate (tzv. Living off the Land), zbog čega se lov mora usmjeriti na detekciju neuobičajenih obrazaca unutar inače normalnih procesa. [3]

Glavni cilj je skratiti "dwell time" - vrijeme od trenutka upada napadača do njegove detekcije - čime se značajno smanjuje potencijalna šteta za organizaciju, što doprinosi kontinuiranom poboljšanju sigurnosnih kontrola. Smanjenje ovog vremena izravno korelira s minimizacijom štete, jer se napadaču onemogućuje postizanje konačnih ciljeva poput eksfiltracije podataka [1]. Na taj način lov na prijetnje ne predstavlja izoliranu aktivnost, već integralni dio cjelokupne strategije kibernetičke sigurnosti.

## 2.2. Threat hunting vs. tradicionalna detekcija

U modernom kibernetičkom okruženju, tradicionalne obrambene mjere više nisu dovoljne za zaustavljanje naprednih prijetnji. Razlika između tradicionalne detekcije i lova na prijetnje leži u samom pristupu sigurnosnom incidentu.

### 2.2.1. Tradicionalna detekcija (Reaktivni pristup)

Tradicionalna detekcija primarno se oslanja na reaktivni model. Sustavi poput antivirusa (AV), vatrozida (eng. Firewall) i klasičnih IDS sustava funkcioniraju na principu detekcije temeljene na potpisima (eng. Signatures).

* **Mehanizam:** Sustav čeka da se dogodi aktivnost koja se podudara s bazom poznatih zlonamjernih uzoraka
* **Problem:** Ako napadač koristi novu metodu ili legitimne sistemske alate za napad, tradicionalna obrana ostaje "slijepa" jer nema odgovarajući potpis za blokiranje
* **Ishod:** Obrana reagira tek nakon što je alarm aktiviran, što često znači da je napadač već ostvario značajan napredak unutar mreže [1].

### 2.2.2. Threat Hunting (Proaktivni pristup)

Lov na prijetnje je proaktivan proces pretraživanja mreža i sustava kako bi se otkrili napadi koji su već zaobišli tradicionalne sigurnosne kontrole.

* **Hipoteza:** Umjesto čekanja na alarm, lovac na prijetnje kreće od pretpostavke da je sustav možda već kompromitiran ("Assume Breach" mentalitet)
* **Mehanizam:** Fokus nije na potpisima, već na ponašanju (eng. Behavioral analysis). Koristeći telemetriju poput Sysmona, analiziraju se anomalije u radu procesa i mrežnog prometa
* **Ishod:** Smanjuje se vrijeme zadržavanja (eng. Dwell time) napadača u sustavu, otkrivajući ga prije nego što izvrši eksfiltraciju podataka

## 2.3. Vrste threat hunting tehnika

Učinkovit lov na prijetnje oslanja se na tri znanstveno utemeljene metodologije koje omogućuju otkrivanje napadača u različitim fazama incidenta.

### 2.3.1. Tehnika temeljena na hipotezama

Ovo je najčešći oblik lova, koji započinje pretpostavkom o prisutnosti specifične napadačke tehnike.

* **Proces:** Lovac koristi MITRE ATT&CK okvir kako bi identificirao taktike (npr. Credential Access) i razvio hipotezu: "Vjerujem da napadač pokušava izvući lozinke iz memorije sustava" [4].
* **Primjena u projektu:** Ova tehnika se koristi za scenarij krađe vjerodajnica (Credential Dumping - T1003.001), gdje se ciljano pretražuju Sysmon logovi za Event ID 10

### 2.3.2. Tehnika temeljena na indikatorima kompromitacije

Ovaj pristup koristi poznate tragove koje su napadači ostavili u prethodnim, dokumentiranim napadima.

* **Proces:** Lovac u sustav unosi poznate IoC (Indicators of Compromise) kao što su specifične IP adrese, hash vrijednosti malicioznih datoteka ili imena domena [4].
* **Primjena u projektu:** Koristi se kod analize Suricata IDS zapisa i Cowrie logova, gdje se traže IP adrese koje su prethodno označene kao izvori brute-force napada

### 2.3.3. Tehnika temeljena na analitici i strojnom učenju

Ovaj pristup se oslanja na prepoznavanje statističkih anomalija u velikim skupovima podataka.

* **Proces:** Umjesto traženja specifičnog potpisa, lovac traži odstupanja od "normalnog" ponašanja sustava (npr. neuobičajeno velik broj DNS upita ili prijava u čudno vrijeme) [4].
* **Primjena u projektu:** Ključna za detekciju DNS eksfiltracije, gdje se analizira mrežni promet kako bi se uočili neuobičajeni obrasci komunikacije koji odstupaju od standardnog mrežnog baselinea

## 2.4. Ciklus lova na prijetnje

Uspješan lov na prijetnje nije slučajan događaj, već strukturirani proces koji se odvija u ponavljajućem ciklusu. To nije jednokratna aktivnost, nego kontinuirani napor usmjeren na jačanje obrambenih sposobnosti organizacije. Vodeći stručnjaci iz industrije ovaj proces opisuju kao petlju lova (eng. Hunting Loop). Ovaj ciklički model osigurava da svaka lovačka ekspedicija rezultira novim znanjem koje se vraća u sustav radi automatizacije budućih detekcija [5].

Ciklički pristup osigurava da se aktivnosti lova temelje na jasnoj logici, dok se stečena saznanja sustavno koriste za poboljšanje detekcije, vidljivosti i sigurnosne arhitekture. U nastavku su opisane četiri ključne, međusobno povezane faze ciklusa lova na prijetnje, koje su vizualno prikazane na Slici 1.

<p align="center">
  <img src="https://github.com/nrastija/threat-hunting-lab/blob/main/results/screenshots/analysis-reporting/CiklusLova.png?raw=true" alt="Slika 1. Ciklus lova na prijetnje" width="500">
  <br>
  <b>Slika 1. Ciklus lova na prijetnje</b>
</p>


### 2.4.1.1. Faza 1: Formuliranje hipoteze (eng. Hypothesis)

Polazna točka i najvažniji korak u svakom lovu na prijetnje jest formuliranje jasne, smislene i provjerljive hipoteze. Lov bez hipoteze uspoređuje se s plovidbom bez karte, jer rezultira neorganiziranim i neučinkovitim pretraživanjem podataka. Hipoteza predstavlja educiranu pretpostavku o aktivnostima napadača unutar okruženja [2].

Hipoteze se najčešće generiraju iz tri glavna izvora. Prvi izvor čine obavještajni podaci o prijetnjama, gdje analitičar koristi vanjske informacije o aktualnim kampanjama i novim tehnikama napada. Drugi izvor hipoteza proizlazi iz dubinskog poznavanja vlastitog okruženja. Razumijevanje normalnog ponašanja sustava i identifikacija najvrjednijih resursa omogućuju uočavanje anomalija koje odstupaju od očekivanog stanja. Treći izvor temelji se na poznatim napadačkim tehnikama, pri čemu se koriste baze znanja poput MITRE ATT&CK® okvira za proaktivno traženje tragova dobro dokumentiranih metoda napada.

### 2.4.1.2. Faza 2: Istraživanje (eng. Investigation)

Nakon formuliranja hipoteze, slijedi fazu istraživanja u kojoj analitičar prikuplja i analizira podatke kako bi hipotezu potvrdio ili opovrgnuo. U ovoj fazi ključno je razmišljati analitički i tražiti suptilne tragove i anomalije, a ne oslanjati se isključivo na postojeće alarme. Istraživanje uključuje korelaciju podataka iz različitih sigurnosnih alata i izvora. Učinkovito istraživanje zahtijeva korelaciju podataka iz različitih izvora, uključujući SIEM za logove i EDR za vidljivost na razini procesa [3].

SIEM sustavi služe kao središnja točka za prikupljanje i pretraživanje sigurnosnih zapisa iz cijelog okruženja, dok EDR rješenja pružaju detaljan uvid u ponašanje procesa i aktivnosti na krajnjim točkama. Dodatno, alati za analizu mrežnog prometa omogućuju otkrivanje sumnjivih komunikacijskih obrazaca, pokušaja eksfiltracije podataka i prikrivene mrežne aktivnosti. Tijekom istraživanja, analitičar se oslanja na poznavanje uobičajenog stanja sustava (eng. baseline) kako bi razlikovao legitimne aktivnosti od potencijalno zlonamjernih [5].

### 2.4.1.3. Faza 3: Otkrivanje (eng. Uncovering)

Ako istraživanje pruži dokaze koji podržavaju hipotezu, proces prelazi u fazu otkrivanja. U ovoj fazi cilj je potvrditi postojanje stvarne prijetnje te razumjeti njezin puni opseg i utjecaj na sustav. Lov na prijetnje u ovoj točki često se preklapa s procesima odgovora na incidente, jer je potrebno rekonstruirati lanac napada i identificirati sve faze kompromitacije.

Analitičar prikuplja i analizira artefakte koje je napadač ostavio, poput zapisa o procesima, mrežnim vezama i promjenama datoteka. Svi nalazi, korišteni upiti i zaključci moraju biti detaljno dokumentirani, budući da čine temelj za daljnje unaprjeđenje sigurnosnih mehanizama. Bitno je identificirati puni opseg kompromitacije kako bi se izbjeglo parcijalno uklanjanje napadača, što bi mu omogućilo brzi povratak u sustav [5].

### 2.4.1.4. Faza 4: Informiranje i obogaćivanje (eng. Informing & Enriching)

Završna faza ciklusa usmjerena je na pretvaranje rezultata ručnog lova u dugoročnu, automatiziranu sigurnosnu vrijednost. Konačni cilj lova je pretvoriti ručno otkriće u automatizirano pravilo detekcije [1].

Osim automatizacije, ova faza uključuje i obogaćivanje sigurnosnih podataka te poboljšanje vidljivosti sustava. Lov često otkriva slijepe točke u vidu nedostatnih logova ili telemetrije, što rezultira preporukama za proširenje izvora podataka. Završetkom ove faze ciklus započinje ispočetka s novom, sofisticiranijom hipotezom, čime se sigurnosne sposobnosti organizacije kontinuirano razvijaju.

## 2.5. Arhitektura sigurnosnog nadzora

Arhitektura sigurnosnog nadzora predstavlja tehničku i organizacijsku osnovu na kojoj se provodi lov na prijetnje. Ključni elementi arhitekture uključuju SIEM sustave, EDR/XDR rješenja, mrežne senzore, sustave za nadzor identiteta te platforme za upravljanje zapisima. Bez sveobuhvatnog prikupljanja logova (eng. log aggregation) i centralizacije podataka u SIEM sustavu, lovac ostaje „slijep“ na lateralno kretanje unutar mreže [5].

Kvalitetna arhitektura sigurnosnog nadzora mora osigurati cjelovitu vidljivost nad informacijskim sustavom. To podrazumijeva prikupljanje podataka s krajnjih točaka, poslužitelja, mrežne infrastrukture i aplikacijskog sloja. Bez takve vidljivosti, aktivnosti postaju ograničene i manje učinkovite, jer analitičar nema dovoljno informacija za prepoznavanje složenih napadačkih lanaca.

## 2.6. MITRE ATT&CK Framework

MITRE ATT&CK je globalno dostupna baza znanja o taktikama i tehnikama napadača temeljena na opažanjima iz stvarnog svijeta. U lovu na prijetnje, ovaj okvir služi kao rječnik i karta. Zbog svoje detaljnosti i široke prihvaćenosti, MITRE ATT&CK je postao temeljni alat u području lova na prijetnje.

U kontekstu lova na prijetnje, MITRE ATT&CK omogućuje analitičarima da strukturiraju hipoteze i analize prema poznatim napadačkim obrascima. Umjesto nasumičnog pretraživanja podataka, lov se usmjerava na specifične tehnike, primjerice lateralno kretanje, eskalaciju privilegija ili zlouporabu legitimnih alata. Time se povećava učinkovitost analize i smanjuje mogućnost previda kritičnih aktivnosti. 

Osim operativne primjene, MITRE ATT&CK služi i kao alat za evaluaciju sigurnosne zrelosti organizacije. Mapiranjem postojećih detekcijskih mehanizama na ATT&CK tehnike moguće je identificirati praznine u pokrivenosti i definirati prioritete za daljnja poboljšanja sigurnosnog nadzora [6].

## 2.7. Metodologija simulacije napada

Metodologija simulacije napada koristi se kako bi se testirala otpornost informacijskih sustava i učinkovitost sigurnosnog nadzora. Cilj ovih aktivnosti nije samo pronalaženje tehničkih ranjivosti, već i evaluacija sposobnosti detekcije i odgovora sigurnosnih timova.

U kontekstu lova na prijetnje, simulacije napada predstavljaju vrijedan izvor uvida u ponašanje sustava pod napadom. Analitičari mogu pratiti kako se generiraju zapisi, koje aktivnosti ostaju neotkrivene i na kojim točkama dolazi do prekida vidljivosti [4]. Ovi uvidi koriste se za poboljšanje lovačkih hipoteza i optimizaciju arhitekture sigurnosnog nadzora.

## 2.8. Analitički proces i dokumentacija lova

Analitički proces lova na prijetnje obuhvaća sustavno prikupljanje, obradu i interpretaciju podataka s ciljem donošenja utemeljenih zaključaka o potencijalnim prijetnjama. Proces započinje razumijevanjem konteksta sustava i poslovnih procesa, što omogućuje pravilnu interpretaciju uočenih anomalija. Bez tog konteksta, postoji rizik pogrešne procjene legitimnih aktivnosti kao zlonamjernih.

Bilježenje svakog koraka, od korištenog SIEM upita do pronađenih artefakata, ključno je za timsku suradnju i edukaciju [2]. Takva dokumentacija služi kao temelj za buduće lovačke aktivnosti i kao vrijedan resurs za edukaciju novih članova tima.

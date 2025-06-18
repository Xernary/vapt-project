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

### Anonymous FTP Login

### Active Scanning & Files Disclosure

### Login as Admin

### Reverse Shell as odoo User

### Privilege Escalation to root

### Lateral Movement

### Privilege Escalation on Second Machine


----
## Conclusion

### Recommendations
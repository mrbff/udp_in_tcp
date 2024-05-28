# udp-in-tcp
Repository privato dedicato all'assignment

## Istruzioni

L'assignment consiste nell'implementazione delle necessarie componenti
software che seguano le seguenti indicazioni:
- un client UDP C1 deve mandare pacchetti di lunghezza e contenuto casuale
  ad un server UDP C2;
- C2 verifica che il contenuto dei pacchetti non sia corrotto mediante
  checksum;
- si immagini che un firewall impedisca lo scambio diretto di pacchetti UDP
  tra C1 e C2;
- per ovviare al blocco, la comunicazione fra C1 e C2 non deve avvenire in
  modo diretto ma deve passare per un tunnel TCP;
- due entitá intermedie, chiamate G1 e G2, dovranno ricevere il traffico UDP,
  scambiarlo mediante connessione TCP ed infine rigirarlo a C2;
- C2 stampa a schermo la dimensione del pacchetto ricevuto e ne salva il
  contenuto in una lista concatenata ordinata per dimensione;
- le componenti devono effettuare una graceful exit alla pressione di Ctrl+C.

Osservazioni:
- se G1 girasse sulla stessa macchina di C1 e cosí anche G2 e C2, un
  osservatore esterno vedrebbe solo traffico TCP;
- qualora si eliminassero G1 e G2, C1 e C2 dovrebbero essere capaci di
  parlare direttamente.


## Tempistiche

Ci si aspetta che l'assignmet venga completato in circa 7 giorni, ma
sulla base dei propri impegni va bene comunicare una tempistica diversa.

## Esecuzione

Il codice dovrá essere caricato su questo reposiory mediante un numero
arbitrario di commit.

Dovranno essere fornite istruzioni riguardo la compilazione e l'esecuzione
delle componenti.

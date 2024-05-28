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

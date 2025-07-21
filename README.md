# ProjectAPS-GR34

Sistema simulato per la gestione sicura e decentralizzata delle credenziali accademiche, basato su firma digitale, Merkle Tree e smart contract per la revoca su blockchain.

## ⚙️ Prerequisiti

Assicurarsi di avere installati:

- Python 3.8+
- [Node.js](https://nodejs.org/)
- [Truffle](https://trufflesuite.com/)

È possibile installare Truffle globalmente con:

```bash
npm install -g truffle
```

## 📦 Installazione delle dipendenze

### 1. Moduli Node per la blockchain
Spostarsi nella cartella `blockchain/` ed eseguire:

```bash
cd blockchain
npm install
```

## 🚀 Avvio della blockchain

Avviare **Ganache** in locale sulla porta `7545`. Possibile farlo:

- con l’app desktop Ganache (configurata su  porta 7545),
- oppure da terminale con:

```bash
ganache --port 7545
```

Poi per compilare e deployare gli smart contract:

```bash
truffle migrate --reset --network development
```


## 🧪 Esecuzione dei test e degli script
`Prima di avviare il file python studente.py si deve avviare lo script python nonce_generator.py (si trova nella direcotry utils)per generare un nonce casuale da far firmare allo studente (si suppone essere l’Università di Salerno).`

Il progetto è suddiviso in script Python autonomi per ogni attore del sistema:

- `rennes.py` → costruzione e firma della credenziale (lato università)
- `student.py` → ricezione e gestione della credenziale da parte dello studente
- `salerno.py` → verifica delle presentazioni ricevute
- `revoke.js` / `check.js` → revoca e verifica su blockchain (nella directory del progetto blockchain/scripts)

## 🔐 Certificati

I certificati delle università sono generati con OpenSSL e salvati in formato PEM. È necessario averli già creati tramite la CA, come descritto nel report tecnico.


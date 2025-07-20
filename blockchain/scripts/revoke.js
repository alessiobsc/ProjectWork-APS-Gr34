module.exports = async function (callback) {
  try {
    const RevocationRegistry = artifacts.require("RevocationRegistry");
    const instance = await RevocationRegistry.deployed();
    const accounts = await web3.eth.getAccounts();

    let rootHash = process.argv[4];

    if (!rootHash) {
      throw new Error("❌ Devi fornire l'hash della root come argomento.");
    }

    // Aggiungi prefisso 0x se manca
    if (!rootHash.startsWith("0x")) {
      rootHash = "0x" + rootHash;
    }

    // Controlla se è un hash valido (hex + lunghezza corretta)
    if (!web3.utils.isHexStrict(rootHash) || rootHash.length !== 66) {
      throw new Error("❌ Root hash non valido. Deve essere una stringa esadecimale lunga 66 caratteri (incluso '0x').");
    }

    await instance.revokeRoot(rootHash, { from: accounts[0] });
    console.log(`✅ Root revocata: ${rootHash}`);
    callback();
  } catch (err) {
    console.error("Errore:", err.message || err);
    callback(err);
  }
};

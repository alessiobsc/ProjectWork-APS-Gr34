const fs = require('fs');
const path = require('path');

module.exports = async function (callback) {
  try {
    const RevocationRegistry = artifacts.require("RevocationRegistry");
    const instance = await RevocationRegistry.deployed();

    const address = instance.address;
    console.log(`✅ Contratto RevocationRegistry deployato all'indirizzo:\n   ${address}`);

    const artifactPath = path.join(__dirname, '../build/contracts/RevocationRegistry.json');
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
    const networks = artifact.networks;

    const networkIds = Object.keys(networks);
    if (networkIds.length === 0) {
      console.log("⚠️  Nessun network trovato nel file di deploy (potrebbe essere stato cancellato Ganache).");
    } else {
      console.log("🌐 Network ID(s):", networkIds.join(', '));
    }
  } catch (err) {
    console.error("❌ Contratto non ancora deployato o errore nel caricamento.");
    console.error(err.message);
  }

  callback();
};

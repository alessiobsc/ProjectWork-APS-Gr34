module.exports = async function (callback) {
  try {
    const RevocationRegistry = artifacts.require("RevocationRegistry");
    const instance = await RevocationRegistry.deployed();

    const hashArg = process.argv[4];
    if (!hashArg) {
      console.log("❌ Root hash mancante.");
      return callback(1);
    }

    const rootHash = hashArg.startsWith("0x") ? hashArg : "0x" + hashArg;

    const result = await instance.isRevoked(rootHash);
    console.log(result ? "revoked" : "valid"); 
    callback();
  } catch (err) {
    console.error("Errore JS:", err.message);
    callback(err);
  }
};

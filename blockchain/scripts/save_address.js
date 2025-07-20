// scripts/save_address.js

const fs = require('fs');
const path = require('path');

module.exports = async function (callback) {
  try {
    const RevocationRegistry = artifacts.require("RevocationRegistry");
    const instance = await RevocationRegistry.deployed();

    const filePath = path.join(__dirname, '../contract_address.txt');
    fs.writeFileSync(filePath, instance.address);
    console.log("📁 Indirizzo salvato in:", filePath);
  } catch (err) {
    console.error("Errore:", err.message);
  }
  callback();
};

'use strict';
var express = require('express');
var bodyParser = require('body-parser');
var eth_crypto = require('eth-crypto');
let bitcoinjs = require('bitcoinjs-lib');
var http_port = 5000

function containsAll(body, requiredKeys) {
    return requiredKeys.every(elem => body.indexOf(elem) > -1) &&
           body.length == requiredKeys.length;
}

var initHttpServer = () => {
    var app = express();
    app.use(bodyParser.json());

    app.post('/crypto2/eth_sign', (req, res) => {
        var values = req.body
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body')
        }

        var required = ["skey", "msg"]
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values')
        }

		try {
            const signature = eth_crypto.sign(values.skey, eth_crypto.hash.keccak256(values.msg));
            res.send({ signature: signature, msg: values.msg });
        } catch (err) {
            res.status(500).send("Signing Error: " + err.message);
        }
    });

    app.post('/crypto2/eth_sign_to_addr', (req, res) => {
        var values = req.body
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body')
        }

        var required = ["signature", "msg"]
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values')
        }

        try {
            // Hash the message
            const messageHash = eth_crypto.hash.keccak256(values.msg);
    
            // Recover the public key from the signature
            const publicKey = eth_crypto.recoverPublicKey(values.signature, messageHash);
    
            // Convert the public key to an Ethereum address
            const address = eth_crypto.publicKey.toAddress(publicKey);
    
            // Send the correct address
            res.send({ address: address });
        } catch (err) {
            console.error("Error recovering address:", err);
            res.status(500).send({ error: "Recover Error: " + err.message });
        }
    });

    app.post('/crypto2/eth_sign_verify', (req, res) => {
        var values = req.body
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body')
        }

        var required = ["address", "msg", "signature"]
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values')
        }

        try {
            //Hash the message
            const messageHash = eth_crypto.hash.keccak256(values.msg);
            // Recover the public key from the signature       
            const recoveredPublicKey = eth_crypto.recoverPublicKey(values.signature, messageHash);
            // Convert the public key to an Ethereum address
            const recoveredAddress = eth_crypto.publicKey.toAddress(recoveredPublicKey);
            //  Compare the recovered address to the provided address
            const isValid = recoveredAddress.toLowerCase() === values.address.toLowerCase();
            // Send the result
            res.send({ valid: isValid ? "valid" : "invalid" });
        } catch (err) {
            console.error("Verification Error:", err);
            res.status(500).send({ error: "Verify Error: " + err.message });
        }
    });

    app.post('/crypto2/btc_skey_to_addr', (req, res) => {
        var values = req.body
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body')
        }

        var required = ["skey"]
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values')
        }

        try {
            // Step 1: Decode the WIF private key
            const keyPair = bitcoinjs.ECPair.fromWIF(values.skey);
    
            // Step 2: Get the public key in compressed format
            const { address } = bitcoinjs.payments.p2pkh({ pubkey: keyPair.publicKey });
    
            // Step 3: Return the Bitcoin address
            res.send({ address: address });
        } catch (err) {
            console.error("Error converting WIF to address:", err);
            res.status(500).send({ error: "Conversion Error: " + err.message });
        }
    });

    app.listen(http_port, () => console.log("Listening http port: " + http_port));
}

initHttpServer();

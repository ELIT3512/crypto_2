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

		// TODO: Not Implemented Yet

        res.send({ signature: "TODO", msg: "TODO"});
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

		// TODO: Not Implemented Yet

        res.send({address: "TODO"});
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

        // TODO: Not Implemented Yet

        res.send({valid: "TODO"});
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

        // TODO: Not Implemented Yet

        res.send({address: "TODO"});
    });

    app.listen(http_port, () => console.log("Listening http port: " + http_port));
}

initHttpServer();

var express = require('express'),
    http = require('http'),
    path = require('path'),
    crypto = require('crypto'),
    app = express(),
    bucket = "For_Testing",
    awsKey = "AKIAJJNKW7VI7KQ6HQNA",
    secret = "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";

app.use(express.logger("dev"));
app.use(express.methodOverride());
app.use(express.bodyParser());
app.use(app.router);

function sign(req, res, next) {

    var fileName = req.body.fileName,
        expiration = new Date(new Date().getTime() + 1000 * 60 * 10).toISOString(); // expire in 10 minutes

    var policy =
    { "expiration": expiration,
        "conditions": [
            {"bucket": bucket},
            {"key": fileName},
            {"acl": 'public-read'},
            ["starts-with", "$Content-Type", ""],
            ["content-length-range", 0, 3145728000]
        ]};

    policyBase64 = new Buffer(JSON.stringify(policy), 'utf8').toString('base64');
    signature = crypto.createHmac('sha1', secret).update(policyBase64).digest('base64');
    res.json({bucket: bucket, awsKey: awsKey, policy: policyBase64, signature: signature});

}

// DON'T FORGET TO SECURE THIS ENDPOINT WITH APPROPRIATE AUTHENTICATION/AUTHORIZATION MECHANISM
app.post('/signing', sign);
app.get('/signing', sign);

app.listen(3004, function () {
    console.log('Server listening on port 3004');
});
'use strict';

const Express = require('express');
const Webtask = require('webtask-tools');
const app = Express();
const bodyParser = require('body-parser');
const querystring = require('querystring');
const crypto = require('crypto');
const rp = require('request-promise');

const urlencodedParser = bodyParser.urlencoded({ extended: true });
const textParser = bodyParser.text({ type: '*/*' });

const registrationKey = 'be6202d6-1e7a-4634-b989-305dec78a81a';
const formUrl = 'https://wt-2117b4787cc0e883d5d156f357f376fa-0.run.webtask.io/form/show?formUrl=https://s3-us-west-2.amazonaws.com/tporter-test/form.html&registrationKey=5b5cc119-cc15-49f9-b33e-38f75419b3e3';

const generateSignedUrl = (requestUrl, requestBody, registrationKey) => {
    const requestTimestamp = new Date().toISOString();

    // Generate canonical query string
    const algorithmParam = 'X-Sig-Algorithm=SIG1-HMAC-SHA256';
    const dateParam = `X-Sig-Date=${requestTimestamp}`;
    const canonicalQueryString = `${querystring.escape(algorithmParam)}&${querystring.escape(dateParam)}`;

    // Generate the string to sign
    const requestBodyHash = crypto.createHash('sha256').update(requestBody).digest('hex');
    const stringToSign = `${requestTimestamp}\n${requestUrl}\n${canonicalQueryString}\n${requestBodyHash}`;

    // Generate the signing key
    let hmac = crypto.createHmac('sha256', registrationKey);
    const signingKey = hmac.update(requestTimestamp).digest();

    // Generate request signature
    hmac = crypto.createHmac('sha256', signingKey);
    const signature = hmac.update(stringToSign).digest('hex');

    // Generate the signed URL
    const signatureParam = `X-Sig-Signature=${signature}`;
    return `${requestUrl}?${algorithmParam}&${dateParam}&${signatureParam}`;
};

app.use('/show', urlencodedParser, function (req, res) {
  rp.get(formUrl)
    .then(form => {
      res.send(require('ejs').render(form, {
        redirectUrl: req.body.redirectUrl 
      }));
    })
    .catch(err => {
      res.status(500).send(err.message).end();
    });
});

app.post('/process', textParser, function (req, res) {
  const form = querystring.parse(req.body);
  const signedUrl = generateSignedUrl(form.redirectUrl, req.body, registrationKey);
  res.set('Location', signedUrl);
  res.status(307).end();
});

module.exports = Webtask.fromExpress(app);

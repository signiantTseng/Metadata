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

const registrationKey = '<Media Shuttle Metadata Registration Key>';
const formUrl = '<URL to HTML document with form>';

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

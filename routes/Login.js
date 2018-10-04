const express = require('express')
const Router = express.Router()
const crypt = require('crypto')

const app = express()

let salt = null;
let sessionId = null;

Router.post('/authenticate', (req, res) => {
    if (req.body.username === 'admin' && req.body.password === 'admin') {
        sessionId = generateSessionId();
        salt = generateSalt(12);
        const csrfToken = generateCSRFToken(sessionId, salt);
        res.cookie('sessionId', sessionId, { maxAge: 900000, httpOnly: false });
        res.cookie('csrfToken', csrfToken, { maxAge: 900000, httpOnly: false });
        // res.json({ success: true, message: 'User Successfully Logged In' });
        res.redirect('/app/make-donation');
    } else {
        // res.json({ success: false, message: 'Incorrect User Credentials' });
        res.redirect('/login-error');
    }
});

Router.post('/make-donation', (req, res) => {
    console.log('cookie: ', req.cookies.csrfToken);
    console.log('body: ', req.body.csrf);
    if (sessionId === req.cookies.sessionId && req.cookies.csrfToken === req.body.csrf) {
        res.redirect('/app/make-donation?success=true');
    } else {
        res.redirect('/app/make-donation?success=false');
    }
});

function generateSessionId() {
    let sha = crypt.createHash('sha256');
    sha.update(Math.random().toString());
    return sha.digest('hex');
}

function generateCSRFToken(sessionId, salt) {
    let hash = crypt.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(sessionId);
    const value = hash.digest('hex');
    return value;
}

function generateSalt(length) {
    return crypt.randomBytes(Math.ceil(length/2))
    .toString('hex') /** convert to hexadecimal format */
    .slice(0,length);
}

module.exports = Router;
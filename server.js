const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')

app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser())

const LoginRoute = require('./routes/Login');

app.use('/', express.static(__dirname + '/views/Login'));
app.use('/app', express.static(__dirname + '/views/Donation'));

app.use('/user', LoginRoute);

app.get('/', function (req, res) {
  // res.send('Hello World!')
  res.sendFile(__dirname + '/views/Login/index.html')
})

app.get('/login-error', function(req, res) {
  res.sendFile(__dirname + '/views/Login/error.html');
})

app.get('/app/make-donation', function (req, res) {
    res.sendFile(__dirname + '/views/Donation/index.html')
})

app.listen(3000, function () {
  console.log('App is listening on port 3000!')
})
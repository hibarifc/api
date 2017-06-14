var express = require('express');
var router = express.Router();
// encryption module
var crypto = require('crypto');
var moment = require('moment');
// user model
var User = require('../models/users');
// jwt model
var Jwt = require('../models/jwt');

/* GET users listing. */
router.post('/login', function (req, res, next) {
  // username
  let username = req.body.username;
  // password
  let password = req.body.password;
  // db connection
  let db = req.dbPool;
  // check username and password
  if (username && password) {
    // encrypt password with md5
    let encryptedPassword = crypto.createHash('md5').update(password).digest('hex');
    // check login
    User.login(db, username, encryptedPassword)
      .then((rows) => {
        // login success
        if (rows.length) {
          // get user id from index 0
          let userId = rows[0].id;
          // sign token 
          let token = Jwt.sign({ userId: userId });
          console.log(token);
          res.send({ ok: true, token: token });
        } else { // login failed
          res.send({ ok: false, error: 'Invalid username/password!' });
        }
      }, (error) => { // query/connection error
        res.send({ ok: false, error: error });
      })
  } else { // incorrect data
    res.send({ ok: false, error: 'Incorrect data!' });
  }
});


//get regis user
router.post('/register', function (req, res, next) {
  let dbPool = req.dbPool;
  let username = req.body.username;
  let password = req.body.password;
  let fullname = req.body.fullname;
  let encryptedPassword = crypto.createHash('md5').update(password).digest('hex');
  if (username && password) {
    // Save user
    User.save(dbPool,username,encryptedPassword,fullname)
      .then((rows) => {
        let user = {
          username: username,
          password: password,
          fullname: fullname,
        };
        res.send({ ok: true, user: user });
      }, (error) => {
        res.send({ ok: false, error: error });
      });
  } else {
    res.send({ ok: false, error: 'Data incomplete' });
  }

});
module.exports = router;

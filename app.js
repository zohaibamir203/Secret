//jshint esversion:6

// Requiring Modules
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const findOrCreate = require('mongoose-findorcreate')

// Setting Plugins to Express
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {}
}));
app.use(passport.initialize());
app.use(passport.session());

// Connecting to Mongoose Database
mongoose.set("strictQuery",false);
mongoose.connect('mongodb://127.0.0.1:27017/userDB',{useNewUrlParser:true});

// mongoose Schema
const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId : String,
    secret : String,
    facebookId: String
})

// Setting Up Passport Local Mongoose Plugin to Schema
userSchema.plugin(passportLocalMongoose);
// Setting up findOrCreate plugin to mongoose schema
userSchema.plugin(findOrCreate);

// mongoose Model
const User = new mongoose.model("User",userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// Using Sign in Google doc on Passport.js serialize and deserialize of model for passport session support
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

// oAuth Passport.js Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// oAuth Passport.js Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home")
})

app.get("/register",function(req,res){
    res.render("register")
})

app.get("/login",function(req,res){
    res.render("login")
})

app.get("/secrets",function(req,res){
    User.find({'secret':{$ne : null}},function(err,result){
        if(err){
            console.log(err);
        }else{
            if(result){
                res.render('secrets',{userWithSecret:result})
            }
        }
    })
})

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect('/login');
    }
})

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


// Login and Logout method is used from Passport Document.
app.get("/logout",function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect('/')
        }
    })
})

app.post("/submit",function(req,res){
    User.findById(req.user.id,function(err,result){
        if(err){
            console.log(err);
        }else{
            if (result){
                result.secret = req.body.secret;
                result.save(function(){
                    res.redirect('/secrets')
                })
            }
        }
    })
})

app.post("/login",function(req,res){
    const user = new User({
        username: req.body.username,
        password : req.body.password
    })
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets')
            })
        }
    })
});

// Register Method is mentioned in doc of Passport Local Mongoose and .authenticate() method is used from passport.
app.post("/register",function(req,res){
    User.register({username : req.body.username},req.body.password,function(err,user){
        if (err){
            console.log(err);
            res.redirect('/register')
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets')
            })
        }
    })
});

app.listen(3000, function() {
    console.log("Server started on port 3000");
  });

// bCrypt Encryption
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

// md5 Encryption
// const md5 = require("md5");

// Mongoose Encryption
// const encrypt = require("mongoose-encryption");

// Schema Encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ['password'] });

// Md5 Syntax
// password : md5(req.body.password)

// Bcrypt login and register

// app.post("/register",function(req,res){
//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         let user = new User({
//             email : req.body.username,
//             password : hash
//         })
//         user.save(function(err){
//             if (err){
//                 console.log(err);
//             }else{
//                 res.render('secrets');
//             }
//         });
//     });
// })

// app.post("/login",function(req,res){
//     User.findOne({email : req.body.username},function(err,result){
//         if (!err){
//             if (result){
//                 bcrypt.compare(req.body.password, result.password).then(function(result) {
//                     if(result === true){
//                         res.render("secrets")
//                     }
//                 });
//             }
//         }
//     });
// });
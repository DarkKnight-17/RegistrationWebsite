const express  = require('express')
const {pool} = require("./dbConfig")
const app = express()
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();

app.use(express.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.use(flash());
app.use(express.static('public'));
app.use(
    session({
      // Key we want to keep secret which will encrypt all of our information
      secret: process.env.SESSION_SECRET,
      // Should we resave our session variables if nothing has changes which we dont
      resave: false,
      // Save empty value if there is no vaue which we do not want to do
      saveUninitialized: false
    })
  );

  const initializePassport = require('./passportConfig')
initializePassport(passport)


app.use(passport.session())
app.use(passport.initialize())
const PORT = 3000

app.get('/users/login',checkAuthenticated, (req,res) => {
    res.render('login')
});

app.get('/', (req,res) => {
    res.render('index')
});

app.get('/users/register',checkAuthenticated, (req,res) => {
    
    res.render('register')
});

app.get('/users/dashboard',checkNotAuthenticated, (req,res) => {
    res.render('dashboard', {user: req.user.username})
    
});

app.post('/users/register',async (req, res) => {
    let  {username, password, password2} = req.body

    errors = []

    if(!username|| !password || !password2){
        errors.push('Please enter all fields')
    }

    if(password.length < 6){
        errors.push('Password must be at least 6 characters long')
    }

    if(password !== password2){
        errors.push("Password don't match")
    }

    if(errors.length > 0){
        res.render('register', {errors: errors})
    }else{
        hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);
        // Validation passed
        pool.query(
          `SELECT * FROM users
            WHERE username = $1`,
          [username],
          (err, results) => {
            if (err) {
              console.log(err);
            }
            console.log(results.rows);

            if (results.rows.length > 0) {
            errors.push("Email already registered");
                res.render("register", {errors: errors});
              }else {
                pool.query(
                  `INSERT INTO users (username, password)
                      VALUES ($1, $2)
                      RETURNING id, password`,
                  [username, hashedPassword],
                  (err, results) => {
                    if (err) {
                      throw err;
                    }
                    console.log(results.rows);
                    req.flash("success_msg", "You are now registered. Please log in");
                    res.redirect("/users/login");
                  }
                );
              }
    }
        );
}   
})

app.get("/users/logout", (req, res) => {
    req.logOut(function(err) {
        if (err) { return next(err); }
        req.flash("success_msg", "You have successfully logged out.");
        res.redirect("/users/login");
    });
    
  });

app.post('/users/login', passport.authenticate('local', {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
  }));

  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect("/users/dashboard");
    }
    next();
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/users/login");
  }


app.listen(PORT, () => {
    console.log(`The app is listenning on port ${PORT}`)
})
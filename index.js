import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import cookieParser from "cookie-parser";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.set("view engine", "ejs");

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect(); 

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// parse cookies if we ever need to inspect them
app.use(cookieParser());

// configure session - default cookie (no maxAge) is a browser-session cookie
app.use(session({
  secret: process.env.SESSION_SECRET, 
  resave: false,
  saveUninitialized: false,
  cookie: {
    // if you want the session to disappear when the browser is closed you
    // *do not* set maxAge or expires; the default behaviour is a session cookie.
    // closing a single tab won't clear it though.
    maxAge: 24 * 60 * 60 * 1000, // 1 day (optional, remove for purely session-only)
  },
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  // passport adds isAuthenticated to the request object, not the response
  console.log(req.user); // logs user when authenticated
  if (req.isAuthenticated()) {
    return res.render("secrets.ejs");
  } else {
    return res.redirect("/login");
  }
});

app.get("/auth/google", passport.authenticate("google", { 
  scope: ["email", "profile"] 
  })
);

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}))


// allow users to explicitly log out
app.get("/logout", (req, res, next) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    // destroy session so cookie is invalidated
    req.session.destroy(() => {
      res.redirect("/");
    });
  });
});


app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  console.log(email);
  console.log(password);

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("<script>alert('Email already exists. Please choose a different email.'); window.location.href='/register';</script>");
    } else {
      //Password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.status(500).send("An error occurred during registration. Please try again later.");
          return;
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, hash]);
          if (result.rows && result.rows[0]) {
            console.log("User registered with ID:", result.rows[0].id);
          }
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/secrets"); 
          });
        }
      });
    }
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).send("An error occurred during registration. Please try again later.");
  }
});

// …existing code…

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

passport.use("local",
  new LocalStrategy(function verify(username, password, done) {
  db.query("SELECT * FROM users WHERE email = $1", [username], (err, result) => {
    if (err) {
      return done(err);
    }
    if (result.rows.length === 0) {
      return done(null, false, { message: "Incorrect username." });
    }
    const user = result.rows[0];
    bcrypt.compare(password, user.password, (err, res) => {
      if (res) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Incorrect password." });
      }
    });
  });
}));

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, 
  async (accessToken, refreshToken, profile, done) => {
  console.log("Google profile:", profile);

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
    if (result.rows.length === 0) {
     const newUser = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [profile.email, "google"]);
     return done(null, newUser.rows[0]);
    } else {
      // Already existing user, just log them in
      done(null, result.rows[0]);
    }
  } catch (err) {
    return done(err);
  }
}));

// store only the user id in the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// load user from database on each request
passport.deserializeUser((id, done) => {
  db.query("SELECT * FROM users WHERE id = $1", [id], (err, result) => {
    if (err) {
      return done(err);
    }
    done(null, result.rows[0]);
  });
});

// …existing code…

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

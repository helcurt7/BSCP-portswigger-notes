
```
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";//this
import session from "express-session";
import passport from "passport";
import {Strategy} from  "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";



const app = express();
const port = 3000;
const saltround =10;
env.config();

const db = new pg.Client({
  user:process.env.PG_USER,
  host: process.env.PG_HOST,
  database : process.env.PG_DATABASE,
  password : process.env.PG_PASSWORD,
  port: process.env.PG_PORT,

});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));














app.use(session({// for cookie seesssiokns 
  secret:process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized:true,
  cookie:{ //ccookies time
    maxAge:1000*60*60*24,
  }
}))



app.use(passport.initialize());//initialsize passsport
app.use(passport.session());//start storing into session with passport
 



app.get("/secrets",async(req,res)=>{
  console.log(req.userinfo) 


  if(req.isAuthenticated()){//authenticated with passport 
    try{

            const secret = await db.query("select secrets from users where email=$1",[req.user.email]);//req.user is buitlin that cb(null,passinvar)-->serialize(cb,userinfo(thisis thepassin var))-->then it is called req.user
            const allsecret= await db.query("select secrets from users where secrets is not null");
            
            console.log(secret);
            const sekret= secret.rows[0].secrets;
            if(sekret){
                    res.render("secrets.ejs",{
                      secret:sekret,
                      Allsecret: allsecret.rows,

                    });
            }else{
                    res.render("secrets.ejs",{secret:"you shd submit a secret", Allsecret: allsecret.rows,})
               

            }
    }catch(err){
      console.log(err);
    }



    

  }else{
    res.redirect("/login")
  }
})

app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs");
  }else{
    res.redirect("/login");
  }
})

app.post("/submit",async(req,res)=>{
   const secret = req.body.secret;
   if(req.isAuthenticated()){
   try{
    await db.query("update users set secrets = $1 where email=$2",[secret,req.user.email]);
    res.redirect("/secrets")
   }catch(err){
    console.log(err)
    res.status(500).send("Something went wrong");
   }}else{
    res.redirect("/login");
   }
})

app.get("/logout", (req, res) => {
  req.logout(function (err) {//got login got logout ma
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});













app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

//oauth ask for permission to get email and profile picture and get it
app.get("/auth/google",passport.authenticate("google",{//use neh below de google strategy we call "google" so here also
  scope:["profile","email"],
  
}))

//after above de but we log in not the AUTHORISED REDIRECT URL http://localhost:3000/auth/google/secrets
app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}))

app.post("/register", async (req, res) => {
  let {password,username}=req.body
  try{
    const checkresult =await db.query("select * from users where email=$1",[username])
    console.log("username : "+username+",password : "+password)

    if(checkresult.rows.length>0){
    res.send("username or email already exist");
    }else{
    

    bcrypt.hash(password,saltround,async(err,hash)=>{
          
        if(err){
          console.log(err);
        }
        else{const result = await db.query("insert into users(email,password) values($1,$2) RETURNING *",[username,hash]);//returning for what
              console.log(result);
              const userinfo = result.rows[0];
              req.login(userinfo,(err)=>{ //login then what redriect to secrets
                console.log(err);
                res.redirect("/secrets")
              })}
    })//this bcrypt


    }

  }catch(err){
    console.log(err)
  }});














app.post("/login",passport.authenticate("local",{ //change postlogin //we call the local strataegy
  successRedirect:"/secrets",//this is connect to req.login
  failureRedirect:"/login",

 

}));

//so when we got 2 strategy we put local
passport.use("local",new Strategy(async function verify(username,password,cb){//make a local strategy u make how it is authenticataed 4th
  console.log(username,password);

    try{
        const checkstuff = await db.query("select * from users where email=$1" ,[username]);
        const userinfo= checkstuff.rows[0];
  if(checkstuff.rows.length>0){

    bcrypt.compare(password,userinfo.password,(err,resp)=>{
      if(err){
        return cb(err);//console.log(err,"error compaaripng password");
      }else{

        if(resp){
        return cb(null,userinfo)}//res.render("secrets.ejs");}
        else{
          return cb(null,false);//res.send("incorrectpassword") // it will redirect to login as u code there
        }
      }

    })}else{
        return cb("user not found")//res.send("username does not exist")
  }    

}catch(err){
      return cb(err)//console.log(err,"unathorised access");
    }
}))


//oauth stuff just below local strategy?
passport.use("google",new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:"http://localhost:3000/auth/google/secrets",
  userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",
},async(accessToken,refreshToken,profile,cb)=>{
  console.log(profile);
  try{
    const result=await db.query("select * from users where email=$1",[profile.email])
    if(result.rows.length===0){
      
      const newUser=await db.query("insert into users (email,password) values($1,$2)",[profile.email,"google"]);
      cb(null,newUser.rows[0])
    }else{
      cb(null,result.rows[0])
    }
  }catch(err){
    cb(err)

  }
}
));

passport.serializeUser((userinfo,cb) =>{//store user info (chekstuff.rows[0] into session  id ,email,password)
  cb(null,userinfo);
});

passport.deserializeUser((userinfo,cb) => {//deserialize for u intot he session to useback
  cb(null,userinfo);
});














app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

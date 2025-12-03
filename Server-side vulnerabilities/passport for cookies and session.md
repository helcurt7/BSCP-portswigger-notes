```

npm i express-session passport passport-local

import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";//this
import session from "express-session";
import passport from "passport";
import {Strategy} from  "passport-local";

app.use(session({// for cookie seesssiokns 
  secret:"bluesecret",
  resave: false,
  saveUninitialized:true,
  cookie:{ //ccookies time
    maxAge:1000*60*60*24,
  }
}))

app.use(passport.initialize());//initialsize passsport
app.use(passport.session());//start storing into session with passport

app.get("/secrets",(req,res)=>{
  console.log(req.userinfo) 
  if(req.isAuthenticated()){//authenticated with passport 
    res.render("secrets.ejs")
  }else{
    res.redirect("/login")
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


"/register" there

        else{const result = await db.query("insert into users(email,password) values($1,$2) RETURNING *",[username,hash]);//returning for what
              console.log(result);
              const userinfo = result.rows[0];
              req.login(userinfo,(err)=>{ //login then what redriect to secrets
                console.log(err);
                res.redirect("/secrets")
              })}










  app.post("/login",passport.authenticate("local",{ //change postlogin
  successRedirect:"/secrets",
  failureRedirect:"/login",

 

}));

passport.use(new Strategy(async function verify(username,password,cb){//make a local strategy u make how it is authenticataed 4th
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

passport.serializeUser((userinfo,cb) =>{//store user info (chekstuff.rows[0] into session  id ,email,password)
  cb(null,userinfo);
});

passport.deserializeUser((userinfo,cb) => {//deserialize for u intot he session to useback
  cb(null,userinfo);
});
```

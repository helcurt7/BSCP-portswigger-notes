npm i passport-google-oauth2

import GoogleStrategy from "passport-google-oauth2";


//oauth ask for permission to get email and profile picture and get it
app.get("/auth/google",passport.authenticate("google",{//use neh below de google strategy we call "google" so here also
  scope:["profile","email"],
  
}))

//after above de but we log in not the AUTHORISED REDIRECT URL http://localhost:3000/auth/google/secrets
app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
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


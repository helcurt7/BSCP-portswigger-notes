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
        else{const result = await db.query("insert into users(email,password) values($1,$2)",[username,hash]);
              console.log(result);
        res.render("secrets.ejs");}
    })//this bcrypt


    }

  }catch(err){
    console.log(err)
  }





});

app.post("/login", async (req, res) => {
    let {password,username}=req.body
      console.log("username : "+username+",password : "+password)

   

  try{
        const checkstuff = await db.query("select * from users where email=$1" ,[username]);
  if(checkstuff.rows.length>0){

    bcrypt.compare(req.body.password,checkstuff.rows[0].password,(err,resp)=>{
      if(err){
        console.log(err);
      }else{

        if(resp){
        res.render("secrets.ejs");}else{
          res.send("incorrectpassword")
        }
      }

    })}else{
    res.send("username does not exist")
  }    

}catch(err){
      console.log(err,"unathorised access");
    }


});

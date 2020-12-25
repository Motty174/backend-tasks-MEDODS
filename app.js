const express=require('express')
const mongoose=require('mongoose')
const bodyParser=require('body-parser')
const bcrypt=require("bcrypt")
const guid=require('guid')
const jwt=require('jsonwebtoken')

const Token=require('./models/token')
const {gettokens,refreshTokens}=require('./functional/token')
const { PORT,MongoURI,secretKeyAccess,secretKeyRefresh} = require('./config/keys')


const app=express()

//Body parser
app.use(bodyParser.urlencoded({extended:true}))
app.use(bodyParser.json())

// Access token is JWT,SHA512 algorithm, Dont save in database
// Give access refresh token for user req.params.id(GUID)
// Example of GUID vlaue
// console.log(guid.create().value)
app.get('/gettoken/:guid_id',async (req,res)=>{

  let c=await Token.findOne({ guid_id : req.params.guid_id })
  if(!guid.isGuid(req.params.guid_id) || c){
    return res.status(404).send('Not allowed')
  }
    gettokens(req.params.guid_id)
      .then(data=>{
            res.json(data)
            })
              .catch(err=>{
               res.status(500).send(err)
            })
})

//Refresh token

app.post('/refreshtoken',(req,res)=>{
  jwt.verify(req.body.token,secretKeyRefresh,(err,result)=>{
    if(err){
     return res.json(err.message)
    }
    refreshTokens(req,res,result)
  })
})

// If you want to check if this works(I did it with postman)
// I wrote it with post but we can cahnge for GET and get tokens from cookie,session or etc. 
// In this case I did with post to finish this task fast.
 
app.post('/check',authToken,(req,res)=>{
  let x=jwt.verify(req.token,secretKeyAccess,err=>{
    if(err){
      res.status(404).send(err.message)
    }else{
      res.send('Good.Token still works.Exp time=2min ')
    }
  })
})

function authToken(req,res,next){
  if(req.body.token){
  req.token=req.body.token
    next()
  }else{
    res.status(403).send('Forbidden,Cant access')
  }
}

// ==================

mongoose.connect(MongoURI,{useNewUrlParser:true,
                            useUnifiedTopology:true,
                            useCreateIndex:true},
                            err=>{
  if(err) throw err
  app.listen(PORT,err=>{
    if(err) throw err
    console.log('MongoDB and Server: Running')
  })
})

const jwt=require('jsonwebtoken')
const guid=require('guid')
const {secretKeyAccess,secretKeyRefresh}=require('../config/keys')
const bcrypt=require('bcrypt')    
const Token=require('../models/token')

async function gettokens(id){           
    try{
        const refreshGuidId=guid.create().value
        const payloadRefresh={
            guid_id: refreshGuidId,
            id_user: id
        }
        const optionsRefresh={ algorithm: 'HS512'};
        const tokenRefresh = jwt.sign( payloadRefresh, secretKeyRefresh, optionsRefresh );
    //Hashing 
        let salt=bcrypt.genSaltSync(10);
        let hashToken=bcrypt.hashSync(tokenRefresh,salt); 
        let mongoSave=await Token.create({guid_id : refreshGuidId, refresh_token: hashToken});                    
        //Access token
        //I gave token Expiry date but you can delete it(as well)
        const payloadAccess={
            guid_id : id    
            }
        const optionsAccess={ algorithm: 'HS512',expiresIn: 20}
        const tokenAccess = jwt.sign(payloadAccess, secretKeyAccess, optionsAccess);

        return {access_token: tokenAccess,
                refresh_token: tokenRefresh}
    }catch(err){
        return Promise.reject('Error: '+err)
    }
}

async function refreshTokens(req,res,result){
    Token.findOne({ guid_id : result.guid_id },(err,currentToken)=>{
        if(err){
            return res.status(405).send('Not valid')
        }    
        if(!currentToken){
            return  res.status(404).send('User not found')
        }
        bcrypt.compare(req.body.token,currentToken.refresh_token,async (err,data)=>{
            if(err){
            return  res.status(401).send('Not allowed refresh token')
            }
            if(!data){
            return res.status(404).send("Cant Match tokens")
            }
            currentToken.deleteOne((err,data)=>{
                if(err){
                   return res.status(500).send("Couldn't refesh")
                }
                gettokens(result.id_user)
                .then(newToken=>{
                    res.json(newToken)
                    })
                        .catch(err=>{
                        res.status(500).send(err)
                    })
            })
            
        })   
    })
    
}

module.exports={
    gettokens,refreshTokens
}
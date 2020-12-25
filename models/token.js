const mongoos=require('mongoose')

const token=mongoos.Schema({
    guid_id: {
        type: String,
        unique: true
    },
    refresh_token: String
})

const Token=mongoos.model('Token',token)
module.exports=Token
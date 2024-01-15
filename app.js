const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const saltRound = 10;
const jwt = require("jsonwebtoken");
const JWT_SECRET_KEY = "MYSECRE_KEREJHJHJHGJdasda"
const cookieParser = require("cookie-parser");

app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(cookieParser());

const users = [
    {

       id:1,
        fullname: "tom",
        email: "tom@tom.com",
        password: "$2b$10$TWelQvjRmDEJwTfXbZSyr.WJze6Phm7tjLeH5fNYx9I3xD6fbdkA."
    },
    {
       id:2,
        fullname: "jerry",
        email: "jerry@jerry.com",
        password: "$2b$10$qa1RYIBZYFtz9gnQO8njDeU0sPZvTni5KpPz37YXncm7ecuIVfkmu"
    }
]

const userAuth = (req,res,next)=>{

    const {token} = req.cookies

    const isValid = jwt.verify(token, JWT_SECRET_KEY);

    if(!isValid){
        return res.status(401).json({
            success:false,
            message:"Invalid Token"
        }); 
    }

    const user = users.find((u) => u.id === isValid.id);

    req.user = user;

    next();

}

app.post("/register", async (req,res)=>{

    const {fullname,email, password} = req.body;

    const hashedPass = await bcrypt.hash(password, saltRound);

    const user = {
        fullname,
        email,
        password:hashedPass  
    }

    if(!user){
        return res.status(500).json({
            success:false,
            message:"User registration failed"
        });
        
    }

    res.status(201).json({
        success:true,
        message:"User registration completed",
        user
    });

});

app.post("/login", async(req,res)=>{

    const{email, password} = req.body;

    const user = users.find((u) => u.email === email);

    if(!user){
        return res.status(404).json({
            success:false,
            message:"Invalid credentials"
        });
        
    }

    const isPassword = await bcrypt.compare(password, user.password);

    if(!isPassword){
        return res.status(401).json({
            success:false,
            message:"Invalid credentials"
        });
    }

    
    const options = {
        id:user.id,
        time:Date.now()
    }

   const token =  jwt.sign(options,JWT_SECRET_KEY,{expiresIn:'5min'});

    res.status(200).cookie("token", token).json({
        success:true,
        message:"User logged in successfully!",
        user
    });
    

});


app.get("/profile",userAuth,(req,res)=>{

    res.status(200).json({
        success:true,
        message:"User Profile Page!",
        user:req.user
    })

})


module.exports = app;
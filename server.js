//Dependencies
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var multer = require('multer');
var db = require('./db');
var upload = multer(); 
var session = require('express-session');
var cookieParser = require('cookie-parser');
var bcrypt = require('bcrypt');
const port = process.env.PORT || 3000;
//Views 
app.set('view engine', 'ejs');
app.set('views','./views');
//Use
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(upload.array());
app.use(cookieParser());
app.use(session({
    secret: "This is my secret",
    resave: true,
    saveUninitialized: true
}));



//routes
app.get('/',(request,response)=>{
    response.redirect('/home');
});

app.get('/home',(request,response)=>{
    if(request.session.user){
        response.render('home',{user:request.session.user});
    } else {
        response.redirect('/login');
    }
});

app.get('/login',(request,response)=>{
    if(request.session.user){
        response.redirect('/home');
    } else {
        var success=[];
        if (request.query.loggedout ==="success"){
            success.push({"message":"Logged out successfully"});
        };        
        response.render('login',{success:success});
    }
});

app.get('/signup',(request,response)=>{
    if(request.session.user){
        response.redirect('/home');
    } else {
        response.render('signup', {data:{"username":"","fullname":"","password":"","password2":""}});
    }
});

app.get('/logout',(request,response)=>{
    if(request.session.user){
        request.session.destroy(function(){            
            response.redirect('/login?loggedout=success');
         });        
    } else {
        response.redirect('/login');
    }
});



//db connection
db.connect((err)=>{
    if(err){
        console.log("Could not connect to db");
        console.log(err);
        process.exit(1);
    } else {
        app.listen(port,()=>{
            console.log("Connect to db");
            console.log("Listening to "+port);
        });
                
    }
});


//SignUp Requests
app.post('/signup',(request,response)=>{
    var formData = request.body;
    var fullname = formData.fullname;
    var username = formData.username;
    var password = formData.password;
    var password2 = formData.password2;
    var errors=[];

    //Checking all are filled
    if((fullname===""||fullname==null)||(username===""||username==null)||(password===""||password==null)||(password2===""||password2==null)){
        errors.push({
            "message":"Please fill all the fields"
        });
    }

    //Restrictions on password
    if(password.length<6){
        errors.push({
            "message":"Minimum 6 characters password needed"
        });
    }

    //Match pasword
    if(password!=password2){
        errors.push({
            "message":"Passwords didn't match"
        });
    }

    //Proceed if no error
    if(errors.length===0){

        var userData = {
            "fullname":fullname,
            "username":username,
            "password":password,
        }

        //finding if user already exists with given username
        db.getDB().collection("users").findOne({"username":username},(err,result)=>{
            if(err){
                console.log(err);
                errors.push({"message":"Some error occured!"});
                response.render('signup',{errors:errors, data:formData});
            } else {
                if(result){
                    errors.push({"message":"Please use another username"});
                    response.render('signup',{errors:errors, data:formData});
                } else {

                    //Register new user by hashing password
                    bcrypt.hash(userData.password, 10, function(err, hash) {
                        if(err){
                            console.log(err);
                            errors.push({"message":"Some error occured!"});
                            response.render('signup',{errors:errors, data:formData});
                        } else {
                            userData.password=hash;                                                          
                            db.getDB().collection("users").insertOne(userData,(err,result)=>{
                                if(err){
                                    console.log(err);
                                    errors.push({"message":"Some error occured!"});
                                    response.render('signup',{errors:errors, data:formData});
                                } else {   
                                    var success = [];                         
                                    success.push({"message":"User registered successfully! Please login"});
                                    response.render('signup',{errors:errors,success:success, data:{"username":"","fullname":"","password":"","password2":""}});
                                }
                            });
                        }
                    });
                    
                }               
                
            }
        });        
    } else {
        response.render('signup',{errors:errors, data:formData});
    }
});


//Login Requests
app.post('/login',(request,response)=>{
    var formData = request.body;
    var username = formData.username;
    var password = formData.password;    
    var errors=[];

    //Checking all are filled
    if((username===""||username==null)||(password===""||password==null)){
        errors.push({
            "message":"Please fill all the fields"
        });
    }

    //Proceed if no error
    if(errors.length===0){
    

        //finding if user exists with given username
        db.getDB().collection("users").findOne({"username":username},(err,result)=>{
            if(err){
                console.log(err);
                errors.push({"message":"Some error occured!"});
                response.render('login',{errors:errors});
            } else {

                if(result){
                    
                    bcrypt.compare(password, result.password, function(err, res) {
                        if(err){
                            console.log(err);
                            errors.push({"message":"Some error occured!"});
                            response.render('login',{errors:errors});
                        } else {
                            if(res===true){                                
                                var user = {
                                    "username":result.username,
                                    "fullname":result.fullname,                                    
                                };
                                console.log(user);
                                request.session.user = user;
                                response.redirect('/home');
                            } else {
                                errors.push({"message":"Wrong password"});
                                response.render('login',{errors:errors});
                            }
                        }
                    });
                } else {
                    errors.push({"message":"Wrong username"});
                    response.render('login',{errors:errors, data:formData});                                        
                }               
                
            }
        });        
    } else {
        response.render('login',{errors:errors});
    }
});


//OPTIONAL CODE
// (Above code would check if user with username is existing before sign up)
//this is just for checking while typing
app.get('/checkforuser/:username',(req,res)=>{
    console.log(req.params.username);
    if(req.params.username){
        db.getDB().collection("users").findOne({"username":req.params.username},(err,result)=>{
            if(err){
                console.log(err);
                errors.push({"message":"Some error occured!"});
                response.render('signup',{errors:errors, data:formData});
            } else {
                if(result){
                    //user found
                    var toSend = {
                        "error":false,
                        "found":true
                    };
                    res.json(toSend);                    
                } else {                    
                    var toSend = {
                        "error":false,
                        "found":false
                    };
                    res.json(toSend);
                }               
                
            }
        });

    } else {
        res.json({"error":true});
    }
});
//OPTIONAL ENDS

app.get('*',(request,response)=>{
    response.render('404');
});
const express = require("express");
const app = express();
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const secretKey = 'your-secret-key';
const cookieParser = require('cookie-parser');


app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(express.static('views'));
app.use(bodyParser.urlencoded({ extended: false }));


let data = require('./data/form.json');

app.get('/dashboard',(req, res) => {
    const token = req.cookies.token;
    if(token){
        res.render('dashboard');
    }
    res.redirect('/login');
    
});

app.get('/login', (req, res) => {

    res.render('login');
});
app.get('/signup', (req, res) => {

    res.render('signup');
});

app.post('/login', [
    
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const userExist = data.find(user => user.email == req.body.email);
    console.log(userExist);

    if (!userExist) {
        return res.status(400).json({ errors: "user does not exist" });
    }

    const comparePassword = bcrypt.compareSync(req.body.password, userExist.password);
    if (!comparePassword) {
        return res.status(400).json({ errors: "invalid password" });
    }


    const token = jwt.sign({ name: userExist.name, role: 'admin'}, secretKey);
    console.log(token);
    
    res.cookie('token', token);

    res.render('login')

})
app.post('/signup', [
    body('name').notEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const userExist = data.find(user => user.email == req.body.email);

    if (userExist) {
        return res.status(400).json({ errors: "user already exists" });
    }

    

    const hashedPassword = bcrypt.hashSync(req.body.password, 12);

    data.push({ name: req.body.name, email: req.body.email, password: hashedPassword });

    fs.writeFile(path.join(__dirname, "./data/form.json"), JSON.stringify(data, null, 2), (err) => {
        if (err) {
            console.error('Error appending to file:', err);
            return;
        }
        console.log('Content appended to file.');
    });
    res.render('signup')


})













app.listen(3000);
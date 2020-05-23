const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');


const User = require('../models/User');

// @route   POST api/users
// @desc    Register a user
// @access  Public
router.post('/', [
    check('name', 'Please add name').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);  
    if(!errors.isEmpty()) { // if "not errors" "is empty", so means there are errors
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { name, email, password } = req.body;

    try {
        let user = await User.findOne( { email }) //check if email has been registered
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({
            name: name,
            email: email,
            password: password
        });

        const salt = await bcrypt.genSalt(10); //use bcrypt to encrypt the password and define how secure the salt is
        user.password = await bcrypt.hash(password, salt)  // takes two params (plain text password & salt) and return a hash version password, then re-assign
        await user.save();
        
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), {
            expiresIn: 360000
        }, (err, token) => {
            if(err) throw err;
            res.json({ token });
        }) //sign to generate a token
    } catch (err) {
        console.error(err.message)
        res.status(500).send('server error')
    }
});

module.exports = router;
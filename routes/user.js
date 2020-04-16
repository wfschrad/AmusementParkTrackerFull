const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

const { csrfProtection, asyncHandler } = require('./utils');
const { check, validationResult } = require('express-validator');
const { Park, Attraction, User } = require('../db/models');
const { loginUser, logoutUser } = require('../auth.js');

router.get('/user/register', csrfProtection, asyncHandler(async (req, res) => {
    const user = User.build();
    res.render('user-register', {
        title: 'Register',
        csrfToken: req.csrfToken(),
        user
    });
}));

const userValidators = [
    check('firstName')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a valid first name')
        .isLength( { max: 50 })
        .withMessage('First name must not be more than 50 characters long'),
    check('lastName')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a valid last name')
        .isLength( { max: 50 })
        .withMessage('Last name must not be more than 50 characters long'),
    check('lastName')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a valid last name')
        .isLength( { max: 50 })
        .withMessage('Last name must not be more than 50 characters long'),
    check('emailAddress')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a value for Email Address')
        .isLength({ max: 255 })
        .withMessage('Email Address must not be more than 255 characters long')
        .isEmail()
        .withMessage('Email Address is not a valid email')
        .custom((value) => {
            return User.findOne({ where: { emailAddress: value } })
                .then((user) => {
                    if (user) {
                        return Promise.reject('The provided Email Address is already in use by another account');
                    }
            });
        }),
    check('password')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a value for Password')
        .isLength({ max: 50 })
        .withMessage('Password must not be more than 50 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/, 'g')
        .withMessage('Password must contain at least 1 lowercase letter, uppercase letter, number, and special character (i.e. "!@#$%^&*")'),
    check('confirmPassword')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a value for Confirm Password')
        .isLength({ max: 50 })
        .withMessage('Confirm Password must not be more than 50 characters long')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Confirm Password does not match Password');
            }
            return true;
        })
];

const loginValidators = [
    check('emailAddress')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a value for Email Address'),
    check('password')
        .exists({ checkFalsy: true })
        .withMessage('Please provide a value for Password')
]

router.post('/user/register', csrfProtection, userValidators, asyncHandler(async (req, res) => {
    const { firstName, lastName, emailAddress, password } = req.body;
    const user = User.build({
        firstName,
        lastName,
        emailAddress,
    });
    const validatorErrors = validationResult(req);
    if (validatorErrors.isEmpty()) {
        const hashedPass = await bcrypt.hash(password, 10);
        user.hashedPassword = hashedPass;
        await user.save();
        loginUser(req, res, user);
        res.redirect('/');
    } else {
        const errors = validatorErrors.array().map(error => error.msg);
        res.render('user-register', {
            title: 'Register',
            user,
            errors,
            csrfToken: req.csrfToken()
        });
    }

}))

router.get('/user/login', csrfProtection, asyncHandler(async (req, res) => {
    res.render('user-login', {
        title: 'Login',
        csrfToken: req.csrfToken()
    });
}));

router.post('/user/login', csrfProtection, loginValidators, asyncHandler(async (req, res) => {
    const { emailAddress, password } = req.body;
    const validatorErrors = validationResult(req);
    let errors = [];

    if (validatorErrors.isEmpty()) {
        const user = await User.findOne( {where: { emailAddress }});
        if (user) {
            const passwordMatch = await bcrypt.compare(password, user.hashedPassword.toString());
            if (passwordMatch) {
                loginUser(req, res, user);
                return res.redirect('/');
            }
        }
        errors.push('Login failed for the provided email address and password');
    } else {
        errors = validatorErrors.array().map(error => error.msg);
    }
    res.render('user-login', {
        title: 'Login',
        emailAddress,
        errors,
        csrfToken: req.csrfToken()
    });
}));

router.post('/user/logout', (req, res) => {
    logoutUser(req, res);
    res.redirect('/user/login');
});

module.exports = router;
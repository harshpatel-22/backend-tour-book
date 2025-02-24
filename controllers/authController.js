const { promisify } = require('util');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');
const crypto = require('crypto');

const signToken = id => {
    const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
    return token;
};

const createSendToken = (user, satusCode, res) => {
    const token = signToken(user._id);

    const cookieOption = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true
    };

    if (process.env.NODE_ENV === 'production') {
        cookieOption.secure = true;
    }

    //remove password from output
    user.password = undefined;

    res.cookie('jwt', token, cookieOption);

    res.status(satusCode).json({
        status: 'success',
        token,
        data: {
            user: user
        }
    });
};

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm,
        passwordChangedAt: req.body.passwordChangedAt,
        role: req.body.role
    });

    createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    // if email and pass exist
    if (!email || !password) {
        next(new AppError('Please provide email and password', 400));
    }

    //check if the user exist and password is correct (output of this will not contain pass)
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new AppError('Incorrect email or password', 401));
    }

    //if everything is ok send jwt to client
    createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
    //get the token and check if it's there
    let token;
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return next(
            new AppError(
                'You are not logged in please  login to get access',
                401
            )
        );
    }

    //validate the token using signature  //verification
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    //check if user still exitst (let the case that user is deleted in meantime)
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
        return next(
            new AppError('user to this token does no longer exist', 401)
        );
    }

    //if user changed password after the token issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(
            new AppError('User changed password! please login again'),
            401
        );
    }

    //grant aceess to protected route
    req.user = currentUser;

    next();
});

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        roles = ['user', 'guide', 'lead-guide', 'admin'];
        // roles ['admin','lead-guide']
        if (!roles.includes(req.user.role)) {
            return next(
                new AppError(
                    'You do not have permission to perform this action',
                    403
                )
            );
        }

        next();
    };
};

exports.forgotPassword = async (req, res, next) => {
    //get user based in posted email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return next(new AppError('user does not exist', 404));
    }

    //generate random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    //send it to user email
    const resetURL = `${req.protocol}://${req.get(
        'host'
    )}/api/v1/resetPassword/${resetToken}`;

    const message = `Forgot your password? submit a patch request with your new password and confirm password to:${resetURL}`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Rest Password token (expires in 10 min)',
            message:'please ignore if you have not perform this action'
        });

        res.status(200).json({
            status: 'success',
            message: 'token sent to email'
        });

        next();
    } catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError('there was an error sending email', 500));
    }
};

exports.resetPassword = async (req, res, next) => {
    // get user based on token
    const hashedToken = crypto
        .createHash('sha256')
        .update(req.params.token)
        .digest('hex');

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() }
    });

    //if token not expired , and there is  user , set new password
    if (!user) {
        return next(new AppError('invalid token or expired', 400));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;

    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();
    //update changed password at the property

    //log the user in and send JWT to user
    createSendToken(user, 200, res);
};

exports.updatePassword = async (req, res, next) => {
    //get user from collection
    const user = await User.findById(req.user.id).select('+password');

    //check if current password is as new pass;
    if (req.body.passwordCurrent === req.body.passwordConfirm) {
        return new AppError(
            'New password must be different from the current password',
            400
        );
    }

    //check if the POSTed password is correct
    if (
        !(await user.correctPassword(req.body.passwordCurrent, user.password))
    ) {
        return next(new AppError('Your current password is wrong', 404));
    }

    //if the pass is correct then update the password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save(); //if we use findbyIdAndUpdate it will not call the middleware for the timestamp and the hashing the passwords

    //log user in with new pass and JWT sent to
    createSendToken(user, 200, res);
};

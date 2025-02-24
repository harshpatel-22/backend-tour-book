const User = require('../models/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const factory = require('./handlerFactory');


const filterObj = (obj ,...allowedFields) => {
    const newObj = {};

    Object.keys(obj).forEach(el => {
        if (allowedFields.includes(el)) {
            newObj[el] = obj[el];
        }
    })

    return newObj;
}
 
exports.getMe = (req, res, next) => {
    req.params.id = req.user.id;
    next();
}
exports.updateMe = async (req, res, next) => {
    // create error if user POST password data
    console.log('here')
    if (req.body.password || req.body.passwordConfirm) {
        return next(new AppError('do not update password here', 400))
    }
    
    //filter the unwanted fields that are not allowed to be updated
    const filteredBody = filterObj(req.body, 'name', 'email')
    
    //update user document
    const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        filteredBody,
        { new: true, runValidators: true }
    );
    
    console.log(updatedUser)
    res.status(200).json({
        status: 'success',
        data: {
            user: updatedUser
        }
    })

    next();
};

exports.deleteMe = async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, { active: false });
    
    res.status(204).json({
        status: 'sccess',
        data:null
    })
    
    next();
}

exports.createUser = (req, res) => {
    res.status(500).json({
        status: 'error',
        message:'this route is not define please use /signup instead'
    })
}

exports.getAllUsers = factory.getAll(User)
exports.getUser = factory.getOne(User);
exports.updateUser = factory.updateOne(User)
exports.deleteUser = factory.deleteOne(User);

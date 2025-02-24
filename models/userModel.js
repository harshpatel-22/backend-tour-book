const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Username must required']
    },
    email: {
        type: String,
        required: [true, 'Please provide email'],
        unique: true,
        lowercase: true,
        validate:[validator.isEmail,'Please provide valid email']
    },
    photo: String,
    role: {
        type: String,
        enum:['user','guide' ,'lead-guide' ,'admin'],
        default: 'user'
    },
    password: {
        type: String,
        required: [true , 'Please provide password'],
        minlength: 8,
        select : false
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please confirm your password'],
        validate: {
            validator: function(el) {
                return el === this.password;
            },
            message:'Password are not same!'
        }
    },
    passwordChangedAt: Date,
    
    passwordResetToken: String,

    passwordResetExpires: Date,

    active: {
        type: Boolean,
        default: true,
        select:false
    }
})

userSchema.pre('save', async function (next) {
    // this only run if the password was actually modified
    if (!this.isModified('password')) return next();

    // hash the password at the cost of 12  
    this.password = await bcrypt.hash(this.password, 12);

    //delete the confirm password feild
    this.passwordConfirm = undefined;
    next();
});

//this is uesd while reset password
userSchema.pre('save', function (next) {
    if (!this.isModified('password') || this.isNew) {
        return next();
    }

    this.passwordChangedAt = Date.now() - 1000; //condition in which token created before timestamp assigned
    next(); 
})

userSchema.pre(/^find/, function (next) {
    //this points to cuurent query
    this.find({ active: {$ne:false} });
    next();

}); 

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    return await bcrypt.compare(candidatePassword, userPassword);
}

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000 , 10)

        console.log(this.passwordChangedAt, JWTTimestamp);

        return JWTTimestamp < changedTimestamp;
    }
    // false means not changed
    return false;
}

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');

    this.passwordResetToken =  crypto.createHash('sha256').update(resetToken).digest('hex');

    this.passwordResetExpires = Date.now() + 10 * 60 * 1000    //plus 10 min in milliseconds
    
    console.log({resetToken} , this.passwordResetToken)

    return resetToken;
}


const User = mongoose.model('User', userSchema);

module.exports = User;
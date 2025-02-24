const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xssClean = require('xss-clean')
const hpp = require('hpp');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const rateLimit = require('express-rate-limit');
const reviewRouter = require('./routes/reviewRoutes')


const app = express();

// 1) MIDDLEWARES

//set security http
app.use(helmet());

//developement logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

//limiter
const limiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.',
    headers: true
});
app.use('/api', limiter);

//body parser
app.use( express.json({limit: '10kb'}));

//data sanitization against nosql query
app.use(mongoSanitize())

// data sanitization against xss
app.use(xssClean())

//http parameter pollution prevention
app.use(
    hpp({
        whitelist: [
            'duration',
            'ratingsQuantity',
            'ratingsAverage',
            'maxGroupSize',
            'difficulty',
            'price']
    })
); 

app.use(express.static(`${__dirname}/public`));

//test middleware
app.use((req, res, next) => {
    req.requestTime = new Date().toISOString();
    next();
});

// 3) ROUTES
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);


app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;

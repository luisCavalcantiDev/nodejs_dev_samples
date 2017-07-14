var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');

var jwt = require('jsonwebtoken');
var config = require('./config');
var User = require('./models/user');
var port = process.env.PORT || 8080;

mongoose.connect(config.database);
app.set('superSecret', config.secret);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(morgan('dev'));

// routes ================

// basic route
app.get('/', function(req, res) {
    res.send('Hello! API está rodando em http://localhost:' + port + '/api');
});

// setup route
app.get('/setup', function(req, res) {
    var nick = new User({
        name: 'Nick Cerminara',
        password: 'password',
        admin: true
    });

    var userLuis = new User({
        name: 'luis.pereira',
        password: '123456',
        admin: true
    });


    nick.save(function(err) {
        if (err) throw err;
        console.log('User ' + nick + ' saved sucessfuly');
    });

    userLuis.save(function(err) {
        if (err) throw err;
        console.log('User ' + userLuis + ' saved sucessfuly');        
    });

    res.json({ sucess: true });
});

// END routes ================

// API ROUTES -------------------

// get an instance of the router for api routes
var apiRoutes = express.Router();

// route to authenticate a user (POST http://localhost:8080/api/authenticate)
apiRoutes.post('/authenticate', function(req, res) {
    User.findOne({
        name: req.body.name
    }, function(err, user) {
        if (err) throw err;
        if (!user) {
            res.json({ sucess: false, message: 'Authentication failed. User not found.' });
        } else if (user) {
            if (user.password != req.body.password) {
                res.json({ sucess: false, message: 'Authentication failed. Wrong password.' });
            } else {

                var token = jwt.sign(user, app.get('superSecret'), {
                    //expiresInMinutes: 1440
                });

                res.json({
                    sucess: true,
                    message: 'Enjoy your token!',
                    token: token
                });
            }
        }
    });
});

//route middleware to verify a token
apiRoutes.use(function(req, res, next) {
    var token = req.body.token || req.query.token || req.headers['x-acess-token'];
    if (token) {
        jwt.verify(token, app.get('superSecret'), function(err, decoded) {
            if (err) {
                return res.json({ sucess: false, message: 'Failed to authenticate token.' });
            } else {
                req.decoded = decoded;
                next();
            }
        });
    } else {
        return res.status(403).send({
            sucess: false,
            message: 'No token provided.'
        });
    }
});

// route to show a random message (GET http://localhost:8080/api/)
apiRoutes.get('/', function(req, res) {
    res.json({ message: 'Welcome to the coolest API on earth!' });
});

//route to return all users (GET http://localhost:8080/api/users)
apiRoutes.get('/users', function(req, res) {
    User.find({}, function(err, users) {
        res.json(users);
    });
});

// apply the routes to our application with the prefix /api
app.use('/api', apiRoutes);

// END API ROUTES -------------------

app.listen(port);
console.log('Magic happens at http://localhost' + port);
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var moment = require('moment');
var jwt = require('jsonwebtoken');
var config = require('./config');
var Cadastro = require('./models/cadastro');
var port = process.env.PORT || 8080;

mongoose.connect(config.database);

app.set('superSecret', config.secret);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(morgan('dev'));

// API ROUTES -------------------

// get an instance of the router for api routes
var apiRoutes = express.Router();

//(GET http://localhost:8080/pmfsc/api/v1/)
apiRoutes.get('/', function(req, res) {
    res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '200', error: '', message: 'Skill Fábrica - API de testes internos para NFS-e Prefeitura Florian[opolis -SC', path: '/pmfsc/api/v1/' });
});

apiRoutes.post('/solicitacao/cadastro', function(req, res) {
    if (!req.body.username || !req.body.password || !req.body.client_id || !req.body.client_secret) {     
        res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Full authentication is required to access this resource', path: '/solicitacao/cadastro'  });

    } else{
            var novoCadastro = new Cadastro({
            username: req.body.username,
            password: req.body.password,
            client_id: req.body.client_id,
            client_secret: req.body.client_secret
        });

        Cadastro.findOne({
            username: novoCadastro.username,
            password: novoCadastro.password,
            client_id: novoCadastro.client_id,
            client_secret: novoCadastro.client_secret

        }, function(err, Cadastro) {
            if (err) throw err;

            if (!Cadastro) {
                novoCadastro.save(function(err) {
                    if (err) throw err;    
                    res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '200', error: '', message: 'aplicação cadastrada com sucesso', path: '/solicitacao/cadastro'  });
                });
            } else{
                res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '200', error: '', message: 'aplicação já cadastrada', path: '/solicitacao/cadastro'  });
            }
        });
    }    
});


//(POST http://localhost:8080/pmfsc/api/v1/autenticacao/oauth/token)
apiRoutes.post('/autenticacao/oauth/token', function(req, res) {
    if (!req.body.grant_type || !req.body.username || !req.body.password || !req.body.client_id || !req.body.client_secret) {
        console.log(req.body);
        console.log(req.headers);
        res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Full authentication is required to access this resource', path: '/autorizador-nfse/oauth/token'  });

    } else{
            Cadastro.findOne({
            username: req.body.username,
            password: req.body.password,
            client_id: req.body.client_id,
            client_secret: req.body.client_secret
        }, function(err, Cadastro) {
            if (err) throw err;
            if (!Cadastro) {
                res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Bad credentials', path: '/autorizador-nfse/oauth/token'  });
            } else if (Cadastro) {
                var token = jwt.sign(Cadastro, app.get('superSecret'), {
                    //expiresInMinutes: 1440
                });

                res.json({
                    access_token: token,
                    token_type: 'access_token'
                });
            }
        });
    }    
});


//route middleware check autorização token
apiRoutes.use(function(req, res, next) {
    var token = req.body.token || req.query.token || req.headers['x-acess-token'];
    if (token) {
        jwt.verify(token, app.get('superSecret'), function(err, decoded) {
            if (err) {                
                return res.json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Failed to authenticate token', path: '/oauth/token'  });;
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


//(GET http://localhost:8080/pmfsc/api/v1/consultas/cadastros)
apiRoutes.get('/consultas/cadastros', function(req, res) {
    Cadastro.find({}, function(err, Cadastro) {
        res.json(Cadastro);
    });
});

//API prefix
app.use('/pmfsc/api/v1', apiRoutes);

// END API ROUTES -------------------

app.listen(port);
console.log('API /pmfsc/api/v1 running --> port: ' + port + ' pid: ' + process.pid.toString());
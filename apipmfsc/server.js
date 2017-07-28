var express = require('express');
var app = express();

var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var moment = require('moment');
var jwt = require('jsonwebtoken');
var config = require('./config');
var Cadastro = require('./models/cadastro');
var util = require('./utils');
var xmlparser = require('express-xml-bodyparser');
var _ = require('lodash');

var port = process.env.PORT || 8080;

mongoose.connect(config.database);

app.set('superSecret', config.secret);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(xmlparser());

app.use(morgan('dev'));

// API ROUTES -------------------

// get an instance of the router for api routes
var apiRoutes = express.Router();

//(GET http://localhost:8080/pmfsc/api/v1/)
apiRoutes.get('/', function(req, res) {
    res.status(200).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '200', error: '', message: 'Skill Fábrica - API de testes internos para NFS-e Prefeitura Florianopolis -SC', path: '/pmfsc/api/v1/' });
});

apiRoutes.post('/solicitacao/cadastro', function(req, res) {
    console.log('/solicitacao/cadastro');
    if (!req.body.username || !req.body.password || !req.body.client_id || !req.body.client_secret) {
        res.status(401).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Full authentication is required to access this resource', path: '/solicitacao/cadastro' });

    } else {
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
                    res.status(200).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '200', error: '', message: 'aplicação cadastrada com sucesso', path: '/solicitacao/cadastro' });
                });
            } else {
                res.status(200).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '200', error: '', message: 'aplicação já cadastrada', path: '/solicitacao/cadastro' });
            }
        });
    }
});


//(POST http://localhost:8080/pmfsc/api/v1/autenticacao/oauth/token)
apiRoutes.post('/autenticacao/oauth/token', function(req, res) {
    console.log('/autenticacao/oauth/token');
    console.log(req.body);
    console.log(req.headers);

    if (!req.body.grant_type || !req.body.username || !req.body.password || !req.body.client_id || !req.body.client_secret) {
        res.status(401).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Full authentication is required to access this resource', path: '/autorizador-nfse/oauth/token' });

    } else {
        Cadastro.findOne({
            username: req.body.username,
            password: req.body.password,
            client_id: req.body.client_id,
            client_secret: req.body.client_secret
        }, function(err, Cadastro) {
            if (err) throw err;
            if (!Cadastro) {
                res.status(400).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '400', error: 'Unauthorized', message: 'Bad credentials', path: '/autorizador-nfse/oauth/token' });

            } else if (Cadastro) {
                var token = jwt.sign(Cadastro, app.get('superSecret'), { expiresIn: 60 });

                res.status(200).json({
                    access_token: token,
                    token_type: 'access_token'
                });
            }
        });
    }
});


//route middleware check autorização token
apiRoutes.use(function(req, res, next) {
    console.log('check autorização token:');

    var auth = req.headers['authorization'];
    if (auth) {
        var temp = auth.split(' ');
        var token = temp[1];
        console.log('token: ' + auth);
        jwt.verify(token, app.get('superSecret'), function(err, decoded) {
            if (err) {
                if (err.name == 'TokenExpiredError') {
                    return res.status(401).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '401', error: 'Unauthorized', message: 'Failed to authenticate token (TokenExpiredError)', path: '/oauth/token' });

                } else {
                    return res.status(400).json({ timestamp: moment().format('YYYY-MM-DD hh:mm:ss'), status: '400', error: 'Unauthorized', message: 'Failed to authenticate token', path: '/oauth/token' });
                }
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

//(POST http://localhost:8080/pmfsc/api/v1/processamento/notas/processa)
apiRoutes.post('/processamento/notas/processa', function(req, res, next) {

    console.log('/processamento/notas/processa');
    console.log(req.body);
    console.log(req.headers);

    if (!req.body) {
        res.status(200).send('<?xml version="1.0" encoding="UTF-8"?><xmlNfpse><message>Problema com integridade do arquivo :: INVALIDO_NAO_INTEGRO</message></xmlNfpse>');

    } else {
        var xmlBase = '<?xml version="1.0" encoding="UTF-8" ?><xmlNfse><bairroPrestador>CENTRO</bairroPrestador><bairroTomador>CENTRO</bairroTomador><baseCalculo>0</baseCalculo><baseCalculoSubstituicao>0</baseCalculoSubstituicao><cfps>9202</cfps><cnpjPrestador>11111111000191</cnpjPrestador><codigoMunicipioTomador>4211900</codigoMunicipioTomador><codigoPostalPrestador>88010000</codigoPostalPrestador><codigoPostalTomador>88020001</codigoPostalTomador><codigoVerificacao>PARAM16</codigoVerificacao><complementoEnderecoTomador>Casa</complementoEnderecoTomador><dadosAdicionais>Venda parcelada</dadosAdicionais><dataEmissao>2017-02-14T00:00:00Z</dataEmissao><dataProcessamento>PARAMAAAA-MM-DDTHH:mm:ss</dataProcessamento><emailPrestador>teste@teste.com.br</emailPrestador><emailTomador>teste@teste.com.br</emailTomador><homologacao>true</homologacao><identificacao>PARAM3</identificacao><identificacaoTomador>83930545001124</identificacaoTomador><inscricaoMunicipalPrestador>0556884</inscricaoMunicipalPrestador><inscricaoMunicipalTomador>0080001</inscricaoMunicipalTomador><itensServico><aliquota>0</aliquota><cst>1</cst><descricaoServico>Extração de Pau Brasil</descricaoServico><idCNAE>8900</idCNAE><quantidade>999</quantidade><valorTotal>9990</valorTotal><valorUnitario>10</valorUnitario></itensServico><logradouroPrestador>FELIPE SCHMIDT, 33333, CPF</logradouroPrestador><logradouroTomador>MORRO DOS CAVALOS</logradouroTomador><nomeMunicipioPrestador>FLORIANOPOLIS</nomeMunicipioPrestador><numeroAEDF>999911</numeroAEDF><numeroEnderecoTomador>123</numeroEnderecoTomador><numeroSerie>2198</numeroSerie><paisTomador>1058</paisTomador><razaoSocialPrestador>TESTE DO PROTOCOLO NOVO</razaoSocialPrestador><razaoSocialTomador>TRIBO CARIJOS</razaoSocialTomador><statusNFPSe>0</statusNFPSe><telefonePrestador>9999999999</telefonePrestador><telefoneTomador>4812345678</telefoneTomador><ufPrestador>SC</ufPrestador><ufTomador>SC</ufTomador><valorISSQN>0</valorISSQN><valorISSQNSubstituicao>0</valorISSQNSubstituicao><valorTotalServicos>9990</valorTotalServicos><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"    xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Sign-9.630221665630206E7"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference Id="RefSignProp-9.268962442139174E7"  Type="http://uri.etsi.org/01903#SignedProperties" URI="#SigProperties-9.659470300833565E7"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>5aBiIeDJPqCxFPWpKyrrrrIj6NaIuoOp70VWatttt=</ds:DigestValue></ds:Reference><ds:Reference Id="RefElement-1.190826287439023E7" URI=""><ds:Transforms><ds:Transform    Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>wtttttttKtoP/2wgJUn6876kXETbWRkkixY=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValueID-5.6422783850940675E7">DtttttttttttcZN/ksJxyibwtTt4nrkPh6VEMuhTl9NWIrHay12nllUqT/cOz/ 6H5GGLv2K8XiCK+BdbMS63y7yf09Xz45wtqT9yJesuOoq430mXYrrrjOfZFToztvlc/mV5Iv5hHb    B1DPNwjwkmg735GGS6rqBkMLQHfaQi7453PIstMtflm0YQlT9oWBubm0Icxff+5Cgk0dCtU54PWP    VHkKrUO7upofukVhKlsg2xziO967dQRpD7G6VZ7KQfbHa2gpjBhkRaz3hX1JtMOgVyP72PI2GRGj    OIXyUkrbe2RpME5UY4ZpKd9XXfqqs2YXItYN+Q==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509SubjectName>EMAILADDRESS=teste@teste.com, L=Fln,   ST=SC, C=BR,    O=BRy Tecnologia, OU=Suporte, CN=Teste</ds:X509SubjectName><ds:X509Certificate>MIIHKjCCBhKgAwIBAgICBW0wDQYJKoZIhvcNAQELBQAwgbMxCzAJBgNVBAYTAkJSMQswCQYDVQQI EwJTQzEWMBQGA1UEBxMNRmxvcmlhbm9wb2xpczEaMBgGA1UEChMRQlJ5IFRlY25vbG9naWEgU0Ex    JTAjBgNVBAsTHEF1dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBCUnkxHjAcBgNVBAMTFUJSeSBBQzIg    LSBDbGFzc2UgMyB2MTEcMBoGCSqGSIb3DQEJARYNYWNAYnJ5LmNvbS5icjAeFw0xNzAyMTMwMDAw    MDBaFw0xODAyMTMxODIyMDBaMIGdMRwwGgYDVQQDExNTYXVsbyBNdXJpbG8gRHVhcnRlMRAwDgYD    VQQLEwdTdXBvcnRlMRcwFQYDVQQKEw5CUnkgVGVjbm9sb2dpYTELMAkGA1UEBhMCQlIxCzAJBgNV    BAgTAlNDMQwwCgYDVQQHEwNGbG4xKjAoBgkqhkiG9w0BCQEWG3NhdWxvbXVyaWxvZHVhcnRlQGdt    YWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANewrVcUqg+87SLIS6B7B8X7    jWdLcAmFiqbaCisH86odcToRNYdmGXQBwj+Fykm5cFjrcD7sxQRvvV1cMjVsHAn3hd/DQ2APKedo    FjAUBgNVBAcTDUZsb3JpYW5vcG9saXMxCzAJBgNVBAgTAlNDMRwwGgYDVQQKExNCUnkgVGVjbm9s    b2dpYSBTLkEuMSEwHwYDVQQLExhBdXRvcmlkYWRlIENlcnRpZmljYWRvcmExGDAWBgNVBAMTD0JS    eSBBQyAtIFJhaXogMjEcMBoGCSqGSIb3DQEJARYNYWNAYnJ5LmNvbS5icoIBGjAPBgNVHRMBAf8E    BTADAgEAMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly93d3cuYnJ5LmNvbS5ici9hYy9jcmwvYnJ5    X2FjMl9jbGFzc2UzX3YxLmNybDCB2QYDVR0gBIHRMIHOMIHLBgsrBgEEAfR/AQMBAzCBuzA2Bggr    BgEFBQcCARYqaHR0cDovL3d3dy5icnkuY29tLmJyL2FjL3BvbGl0aWNhcy9kcGMucGRmMIGABggr    BgEFBQcCAjB0GnJDZXJ0aWZpY2FkbyBkaWdpdGFsIGF1dGVudGljYWRvIHBvciBBdXRvcmlkYWRl    IGRlIFJlZ2lzdHJvIGNyZWRlbmNpYWRhLiBCUnkgVGVjbm9sb2dpYSBTLkEuIGh0dHA6Ly93d3cu    YnJ5LmNvbS5ici4wTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LmJyeS5j    sdsdsb20uYnIvYWMvY3J0L2FjX2JyeV9jbGFzc2UzX3YxLnA3YjAdBgNVHSUEFjAUBggrBgEFBQc    KwYBBQUHAwIwDgYDVR0PAQH/BAQDAgXgMIGnBgNVHREEgZ8wgZygQQYFYEwBAwGgOAQ2MTMwMjE5    OTE2NTcxMDk5MTk1MzAwMDMyNDIzNDIzMDAwMDAwMDAyMTM0MjM0MTIzNDIxMzQyoCEGBWBMAQMF    oBgEFjAwMDAwMDA0MjE0MTM0MjAxMjRGTE6gFwYFYEwBAwagDgQMMDAwMDAwMDM0MjQygRtzYXVs    b211cmlsb2R1YXJ0ZUBnbWFpbC5jb20wDQYJKoZIhvcNAQELBQADggEBAARNqjVoU5WN/5mTuZpn    d/yqUTV8pQu0EkHs9/Bs9u+v2zJoYlQxwl6wEyX49bhmkAYX9MsxS8SVJE4iDGvU/YselaKkcmSB    ESaPcx5c5blVOKab9RmZ9rDtDFeymMcyeB64/dCmHto2UIdLe3AuLl2zWNjolsT/5IfqS2ORrTUO    rPn0sWkiXzSZ4rSJ6bTw6VpYpg/SV4mOzhMiWHQQHdKhTEGR8fA8wCS3wyxN7C4xLEVy6XvAaDhv    z0EflxPdsVm0KNV6X+ttIghgt2m1+bGFrDgw6noaw1Tc8sIX6RVLCfml4EqJSkrcZEf6TwDPM9Db    jHsaW/dIXZNu7hIRa88=</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties Id="QualProperties-6.905158899850324E7"    Target="#Sign-9.630221665630206E7"><xades:SignedProperties Id="SigProperties-9.659470300833565E7"><xades:SignedSignatureProperties><xades:SigningTime>2017-03-09T13:20:30.230-03:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>1q7dgQpRd+Pkp/3xPcne0LkphqkQeod1oPFN42Ms2nc=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>EMAILADDRESS=ac@bry.com.br, CN=BRy AC2 - Classe 3 v1, OU=Autoridade Certificadora BRy, O=BRy Tecnologia  SA, ST=SC, L=Florianopolis, C=BR</ds:X509IssuerName><ds:X509SerialNumber>1389</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate><xades:SignaturePolicyIdentifier><xades:SignaturePolicyId><xades:SigPolicyId><xades:Identifier Qualifier="OIDAsURN">urn:oid:2.16.76.1.7.1.7.2.3</xades:Identifier></xades:SigPolicyId><xades:SigPolicyHash><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>pWNimkGlQBbpWipRz6mDPU8Y+/JQy+d+ioZflOpXzls=</ds:DigestValue></xades:SigPolicyHash><xades:SigPolicyQualifiers><xades:SigPolicyQualifier><xades:SPURI>http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_3.xml</xades:SPURI></xades:SigPolicyQualifier></xades:SigPolicyQualifiers></xades:SignaturePolicyId></xades:SignaturePolicyIdentifier></xades:SignedSignatureProperties></xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments" /><xades:EncapsulatedTimeStamp Id="CarimboTempo-9.689010040475973E7">MIAGCSqGSIb3DQEHAqCAMIIKPwIBAzELMAkGBSsOAwIaBQAwggE+BgsqhkiG9w0BCRABBKCCAS0E   ggEpMIIBJQIBAQYKKwYBBAH0fwIBADAxMA0GCWCGSAFlAwQCAQUABCCrFf0kwVnpQKgxobICP14c    1q44WFkIs1OHjeh6NghfmQIBQhgTMjAxNzAzMDkxNjIwNTkuNjI4WgEB/wIItCXtUDS6bw+ggbuk    gbgwgbUxLjAsBgNVBAMMJVByZWZlaXR1cmEgTXVuaWNpcGFsIGRlIEZsb3JpYW5vcG9saXMxCzAJ    BgNVBAYTAkJSMQswCQYDVQQIDAJTQzEWMBQGA1UEBwwNRmxvcmlhbm9wb2xpczEYMBYGA1UECgwP    QlJ5IFRlY25vbG9naWEgMSUwIwYJKoZIhvcNAQkBFhZhdGVuZGltZW50b0BicnkuY29tLmJyMRAw    DgYDVQQLDAdTdXBvcnRloIIGkzCCBo8wggV3oAMCAQICAgTTMA0GCSqGSIb3DQEBCwUAMIGzMQsw    CQYDVQQGEwJCUjELMAkGA1UECBMCU0MxFjAUBgNVBAcTDUZsb3JpYW5vcG9saXMxGjAYBgNVBAoT    EUJSeSBUZWNub2xvZ2lhIFNBMSUwIwYDVQQLExxBdXRvcmlkYWRlIENlcnRpZmljYWRvcmEgQlJ5    MR4wHAYDVQQDExVCUnkgQUMyIC0gQ2xhc3NlIDMgdjExHDAaBgkqhkiG9w0BCQEWDWFjQGJyeS5j    b20uYnIwHhcNMTYxMTA5MDAwMDAwWhcNMTkxMTA5MTgyMjAwWjCBtTEuMCwGA1UEAwwlUHJlZmVp    dHVyYSBNdW5pY2lwYWwgZGUgRmxvcmlhbm9wb2xpczELMAkGA1UEBhMCQlIxCzAJBgNVBAgMAlND    MRYwFAYDVQQHDA1GbG9yaWFub3BvbGlzMRgwFgYDVQQKDA9CUnkgVGVjbm9sb2dpYSAxJTAjBgkq    hkiG9w0BCQEWFmF0ZW5kaW1lbnRvQGJyeS5jb20uYnIxEDAOBgNVBAsMB1N1cG9ydGUwggEiMA0G    CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGEvurAkvPrlEdkCsg0zJBeeCwITlTciQ4DLYXiqmX    NyupKdzfV7SQf6JhM4hP6mmxpWK8mOwjcur4AurwsS4JF4SNzgBYpvnZ4pJATBbn7Murtc4njQ/F    T1UyKnmfyD1IwncZYARzaCOnRpQuhgknaU50dx4fe/C97b+Ya2z1cI7GjPzkLRovbE5DItV3efjT    T1UyKnmfyD1IwncZYARzaCOnRpQuhgknaU50dx4fe/C97b+Ya2z1cI7GjPzkLRovbE5DItV3efjT    Oi8vd3d3LmJyeS5jb20uYnIvYWMvcG9saXRpY2FzL2RwYy5wZGYwgYAGCCsGAQUFBwICMHQackNl    cnRpZmljYWRvIGRpZ2l0YWwgYXV0ZW50aWNhZG8gcG9yIEF1dG9yaWRhZGUgZGUgUmVnaXN0cm8g    Y3JlZGVuY2lhZGEuIEJSeSBUZWNub2xvZ2lhIFMuQS4gaHR0cDovL3d3dy5icnkuY29tLmJyLjBO    BggrBgEFBQcBAQRCMEAwPgYIKwYBBQUHMAKGMmh0dHA6Ly93d3cuYnJ5LmNvbS5ici9hYy9jcnQv    YWNfYnJ5X2NsYXNzZTNfdjEucDdiMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAsGA1UdDwQEAwIG    wDANBgkqhkiG9w0BAQsFAAOCAQEAOROXZPpnyOWtn4CDqMU1Ppk8vBwOOlcbtyda3h5PwI2llUdU    +06gXfIdSX+9rb5T2hoBhMWVqVj36sYwhYN03WPnRYKrYge7obVyjOgwHJcSCnAK9luGtXLmDo7z    K+eGh9Zi7wfjvFTA+ClsHQE/OCLFOgQ8mR6SWBcZ6e1GSRH5MEneTSWwlOEVcL/ITw19cyTbpKEo    xiDen//gpW0bVIUXVssiZViGI17YK7WAa62TZYaL3danRPW02hyiH6luWNoH2EBvGgXyToMYTZkx    KTenahVOR8gbFyXwXBDKOU3Otx8o4exOysFZf3ZvfJ3SptKpIE+KJF7JiSqje+zQ1TGCAlIwggJO    AgEBMIG6MIGzMQswCQYDVQQGEwJCUjELMAkGA1UECBMCU0MxFjAUBgNVBAcTDUZsb3JpYW5vcG9s    aXMxGjAYBgNVBAoTEUJSeSBUZWNub2xvZ2lhIFNBMSUwIwYDVQQLExxBdXRvcmlkYWRlIENlcnRp    ZmljYWRvcmEgQlJ5MR4wHAYDVQQDExVCUnkgQUMyIC0gQ2xhc3NlIDMgdjExHDAaBgkqhkiG9w0B    CQEWDWFjQGJyeS5jb20uYnICAgTTMAkGBSsOAwIaBQCgbjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN    AQkQAQQwIwYJKoZIhvcNAQkEMRYEFKHAtU7a3yvWu8Wv4Wu0Uiequ3/GMCsGCyqGSIb3DQEJEAIM    MRwwGjAYMBYEFPDXkutIYVuqXtRZ5DLXF87GaSwnMA0GCSqGSIb3DQEBAQUABIIBAKZh2d8k0Fof    zr5nrDjzuhUTXFOF2avFoDgUv4AyB1sOSOSDNNQBtzBSuekcuyR3+Rh0FvUT7/K/kY0e4QVOSuRp    5fYtf/f2XwiMMTj5lKNXb0cMIIHCp9JNd7JEZELHUse7zcR0iqDhBtHR4G+P14jxYWpP186VeYBI    GHxQNW2o/KMgnZezgVv9CyaFOzzFJlssxXT4fP5yu5F+RdqKw5vTyJTE8seZYQzDM8G0A7OTkjUS    9UIGWICma5w/ZTxTtIHiuFiTiLxNGj7v7LRFxAw+yKlqxU6IEZ84znBOG2LgsUPZ0BPvLJ9Kyr+4    kgxWixrsmfqBp2G8KME8kYfgA80AAAAA</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></xmlNfse>'
        var xmlTemp = xmlBase;

        var _codigoVerificacao = _.toUpper(util.randomString(16));
        var _identificacao = _.toUpper(util.randomString(3));
        var _dtProcessamento = moment().format('YYYY-MM-DD hh:mm:ss');

        console.log('autorizacao NFPS-e')
        console.log("codigoVerificacao=>" + _codigoVerificacao);
        console.log("identificacao=>" + _identificacao);
        console.log("dataProcessamento=>" + _dtProcessamento);

        xmlTemp = xmlTemp.replace(/PARAM16/, _codigoVerificacao);
        xmlTemp = xmlTemp.replace(/PARAM3/, _identificacao);
        xmlTemp = xmlTemp.replace(/PARAMAAAA-MM-DDTHH:mm:ss/, _dtProcessamento);

        res.contentType('application/xml');
        res.status(200).send(xmlTemp);
    }
});


//(GET http://localhost:8080/pmfsc/api/v1/consultas/cadastros)
apiRoutes.get('/consultas/cadastros', function(req, res) {
    console.log(req.body);
    console.log(req.headers);

    Cadastro.find({}, function(err, Cadastro) {
        res.json(Cadastro);
    });
});

//API prefix
app.use('/pmfsc/api/v1', apiRoutes);

// END API ROUTES -------------------

app.listen(port);
console.log('API /pmfsc/api/v1 running --> port: ' + port + ' pid: ' + process.pid.toString());
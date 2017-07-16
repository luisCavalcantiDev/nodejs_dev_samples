var mongoose = require('mongoose');
var Schema = mongoose.Schema;

module.exports = mongoose.model('Cadastro', new Schema({
	username: String,
	password: String,
	client_id: String,
	client_secret: String
}));
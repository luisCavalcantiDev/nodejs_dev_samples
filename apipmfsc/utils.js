'use strict';

var util = require('util'),
    _ = require('lodash'),
    moment = require('moment');

var Util = {};

Util.customRandom = function(dictonary, length) {
	if (!length) {
		length = 6;
	}
	var array = [],
		CHARS = dictonary.split('');

	for (var i = 0; i < length; i++) {
		array.push(CHARS[Math.floor(Math.random() * dictonary.length)]);
	}
	return array.join('');
};

Util.randomString = function(length) {
	var dictonary = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	return Util.customRandom(dictonary, length);
};

module.exports = Util;
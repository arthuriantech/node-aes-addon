addon = require('./build/Release/aes256.node');

key = Buffer.from('00000000000000000000000000000000')
str = 'Hello world';
len = str.length + 16 - (str.length % 16) 
pad = len - str.length

data = Buffer.alloc(len, pad);
data.write(str, 0, str.length, 'utf8')

encrypted = addon.encrypt(key, data)
console.log(encrypted.toString('base64'))

decrypted = addon.decrypt(key, encrypted)
console.log(decrypted.toString())

// Check here http://aes.online-domain-tools.com/

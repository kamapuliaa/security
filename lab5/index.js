'use strict';

const crypto = require('crypto');

function generateKeyPair(length) {
  const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
    modulusLength: length,
  });
  return {
    public: publicKey,
    private: privateKey,
  };
};

function encrypt(data, publicKey) {
   return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data),
  );
}

function decrypt(data, privateKey) {
  return crypto
    .privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      data,
    )
    .toString();
}

(function main() {
  const data = 'Kamilla';
  const {public, privateKey} = generateKeyPair(2048);
  const encrypted = encrypt(data, public);
  const decrypted = decrypt(encrypted, private);

  console.log({
    isEqual: decrypted === data,
    data,
    encrypted: encrypted.toString(),
    decrypted,
  });
})();

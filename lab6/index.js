'use strict';

const crypto = require('crypto');

function generateKey(length) {
  const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
    modulusLength: length,
  });
  return {
    public: publicKey,
    private: privateKey,
  };
};

function signMessage(message, privateKey) {
  const signature = crypto.sign('sha256', Buffer.from(message), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  return signature;
};

function verify(message, signature, publicKey) {
  const isVerified = crypto.verify(
    'sha256',
    Buffer.from(message),
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    signature,
  );
  return isVerified;
};

(function main() {
  try {
    const message = 'Kamilla';
    const keys = generateKey(2048);
    const signature = signMessage(message, keys.private);
    const invalidSignature = Buffer.from(new Array(10).fill(0).map(() => 1));
    console.log({
      case: 'valid',
      message,
      signature: signature.toString(),
      isVerified: verify(message, signature, keys.public),
    });
    console.log({
      case: 'invalid',
      message,
      signature: invalidSignature.toString(),
      isVerified: verify(message, invalidSignature, keys.public),
    });
  } catch (err) {
    console.log(err);
  }
})();

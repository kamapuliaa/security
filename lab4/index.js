const forge = require('node-forge');
const BigNumber = require('bignumber.js');

function genaratePrimePair(bits) {
  const options = {
    algorithm: {
      name: 'PRIMEINC',
      workers: -1,
    },
  };
  return new Promise((res, rej) => {
    forge.prime.generateProbablePrime(bits, options, (err, num) => {
      if (err) return rej(err);
      res(new BigNumber(num.toString()));
    });
  });
}

(async () => {
  try {
    const [a, b] = await Promise.all([genaratePrimePair(1024), genaratePrimePair(1024)]);

    console.log({
      a: a.toString(10),
      b: b.toString(10),
    });

    //Operations example
    console.log({
      sum: a.plus(b).toString(10),
      mult: a.multipliedBy(b).toString(10),
      mod: a.modulo(2).toString(10),
      pow: a.exponentiatedBy(2).toString(10),
    });
  } catch (err) {
    console.error(
      {
        message: 'main error',
        error: err,
      }
    );
  }
})();

# coconut-chainspace
[![license](https://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/asonnino/coconut-chainspace/blob/master/LICENSE) 


This is the [Coconut](https://github.com/asonnino/coconut) smart contract library implemented for [Chainspace](https://github.com/chainspace), as described in section 4.1 of the [Coconut paper](https://arxiv.org/abs/1802.07344). The goal is to enable other application-specific smart contracts to conveniently use the Coconut cryptographic primitives through cross-contract calls. As examples, we provide implementation of:
  - [Privacy-preserving e-petition contract](https://github.com/asonnino/coconut-chainspace/blob/master/contracts/petition.py)
  - [Coin tumbler contract](https://github.com/asonnino/coconut-chainspace/blob/master/contracts/tumbler.py)

The Coconut cryptographic scheme is available [here](https://github.com/asonnino/coconut), and a link to the full paper is available [here](https://arxiv.org/abs/1802.07344).


## Pre-requisites
Install the Chainspace Contract Framework as described [here](https://github.com/chainspace), and Coconut as described [here](https://github.com/asonnino/coconut#install)

## Test
Tests can then be run as follows:
```
$ pytest -v tests/
```


## Contribute
Feel free to send a PR if you wrote other Chainspace smart contracts based on Coconut!


## License
[The BSD license](https://opensource.org/licenses/BSD-3-Clause)

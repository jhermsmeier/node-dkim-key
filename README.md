# DKIM Key
[![npm](https://img.shields.io/npm/v/dkim-key.svg?style=flat-square)](https://npmjs.com/dkim-key)
[![npm](https://img.shields.io/npm/l/dkim-key.svg?style=flat-square)](https://npmjs.com/dkim-key)
[![npm downloads](https://img.shields.io/npm/dm/dkim-key.svg?style=flat-square)](https://npmjs.com/dkim-key)

## Install via [npm](https://npmjs.com)

```sh
$ npm install dkim-key
```

## Usage

```js
const DKIMKey = require( 'dkim-key' )
```

```js
var txtRecord = 'v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWyktrIL8DO/+UGvMbv7cPd/Xogpbs7pgVw8y9ldO6AAMmg8+ijENl/c7Fb1MfKM7uG3LMwAr0dVVKyM+mbkoX2k5L7lsROQr0Z9gGSpu7xrnZOa58+/pIhd2Xk/DFPpa5+TKbWodbsSZPRN8z0RY5x59jdzSclXlEyN9mEZdmOiKTsOP6A7vQxfSya9jg5N81dfNNvP7HnWejMMsKyIMrXptxOhIBuEYH67JDe98QgX14oHvGM2Uz53if/SW8MF09rYh9sp4ZsaWLIg6T343JzlbtrsGRGCDJ9JPpxRWZimtz+Up/BlKzT6sCCrBihb/Bi3pZiEBB4Ui/vruL5RCQIDAQAB;n=2048,1452627113,1468351913'
```

```js
var key = DKIMKey.parse( txtRecord )
```

```js
DKIMKey {
  version: 'DKIM1',
  type: 'rsa',
  hashes: undefined,
  service: undefined,
  flags: undefined,
  note: '2048,1452627113,1468351913',
  granularity: undefined,
  data: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWyktrIL8DO/+UGvMbv7cPd/Xogpbs7pgVw8y9ldO6AAMmg8+ijENl/c7Fb1MfKM7uG3LMwAr0dVVKyM+mbkoX2k5L7lsROQr0Z9gGSpu7xrnZOa58+/pIhd2Xk/DFPpa5+TKbWodbsSZPRN8z0RY5x59jdzSclXlEyN9mEZdmOiKTsOP6A7vQxfSya9jg5N81dfNNvP7HnWejMMsKyIMrXptxOhIBuEYH67JDe98QgX14oHvGM2Uz53if/SW8MF09rYh9sp4ZsaWLIg6T343JzlbtrsGRGCDJ9JPpxRWZimtz+Up/BlKzT6sCCrBihb/Bi3pZiEBB4Ui/vruL5RCQIDAQAB',
  unknownTags: undefined
}
```

# DKIM (DomainKeys Identified Mail) Key
[![build status](http://img.shields.io/travis/jhermsmeier/node-dkim-key.svg?style=flat)](http://travis-ci.org/jhermsmeier/node-dkim-key)
[![npm](http://img.shields.io/npm/v/dkim-key.svg?style=flat)](https://npmjs.org/dkim-key)
![downloads](http://img.shields.io/npm/dm/dkim-key.svg?style=flat)

## Install with [npm](//npmjs.org)
```
npm install dkim-key
```

## Usage

```js
var DKIMKey = require( 'dkim-key' )
```

Suppose you have the content of the `xxx._domainkey.<domain>` TXT DNS record:
```
k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQs8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbbhzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5OctMEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598HY+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB
```

Parse the TXT record:
```js
var key = DKIMKey.parse( txtRecord )
```

```js
{
  flags: null,
  granularity: null,
  hash: null,
  key: <Buffer 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d ...>,
  notes: null,
  service: null,
  type: 'rsa',
  version: null
}
```

Or create a signature header:
```js
var key = new DKIMKey({
  type: 'rsa',
  key: <Buffer 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d ...>
})
```

```js
key.toString()
```

## API

Constructor:

- new Key( options )
- Key.create( options )
- Key.parse( txtRecord )

Methods:

- key.parse( txtRecord )
- key.toString()

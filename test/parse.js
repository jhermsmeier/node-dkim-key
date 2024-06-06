const assert = require( 'node:assert' )
const DKIMKey = require( '..' )

context( 'DKIMKey.parse()', () => {

  test( 'Bare minimum', () => {

    var key = DKIMKey.parse( 'v=DKIM1; p=' )

    assert.strictEqual( key.version, 'DKIM1' )
    assert.equal( key.data, null )
    assert.strictEqual( key.isRevoked(), true )

  })

  test( 'Empty key data', () => {

    var key = DKIMKey.parse( 'v=DKIM1; p=IA==' )

    assert.strictEqual( key.version, 'DKIM1' )
    assert.strictEqual( key.data, 'IA==' )
    assert.strictEqual( key.isRevoked(), true )

  })

  test( 'Acceptable hashes', () => {

    var key = DKIMKey.parse( 'v=DKIM1; h=sha256; p=' )
    assert.strictEqual( key.isAcceptableHash( 'sha1' ), false )
    assert.strictEqual( key.isAcceptableHash( 'sha256' ), true )

    var key = DKIMKey.parse( 'v=DKIM1; p=' )
    assert.strictEqual( key.isAcceptableHash( 'sha1' ), true )
    assert.strictEqual( key.isAcceptableHash( 'sha256' ), true )
    assert.strictEqual( key.isAcceptableHash( 'anything, really' ), true )

  })

  context( 'Flags', () => {

    test( 'Test mode', () => {
      var key = DKIMKey.parse( 'v=DKIM1; t=y; p=' )
      assert.strictEqual( key.isTest(), true )
      assert.strictEqual( key.isStrict(), false )
    })

    test( 'Strict mode', () => {
      var key = DKIMKey.parse( 'v=DKIM1; t=s; p=' )
      assert.strictEqual( key.isTest(), false )
      assert.strictEqual( key.isStrict(), true )
    })

    test( 'Strict & test mode', () => {
      var key = DKIMKey.parse( 'v=DKIM1; t=y:s; p=' )
      assert.strictEqual( key.isTest(), true )
      assert.strictEqual( key.isStrict(), true )
    })

  })

  context( 'In the wild', () => {

    // The only key record I've seen so far that has a note
    test( 'outlook.com selector1', () => {

      var record = 'v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWyktrIL8DO/+UGvMbv7cPd/Xogpbs7pgVw8y9ldO6AAMmg8+ijENl/c7Fb1MfKM7uG3LMwAr0dVVKyM+mbkoX2k5L7lsROQr0Z9gGSpu7xrnZOa58+/pIhd2Xk/DFPpa5+TKbWodbsSZPRN8z0RY5x59jdzSclXlEyN9mEZdmOiKTsOP6A7vQxfSya9jg5N81dfNNvP7HnWejMMsKyIMrXptxOhIBuEYH67JDe98QgX14oHvGM2Uz53if/SW8MF09rYh9sp4ZsaWLIg6T343JzlbtrsGRGCDJ9JPpxRWZimtz+Up/BlKzT6sCCrBihb/Bi3pZiEBB4Ui/vruL5RCQIDAQAB;n=2048,1452627113,1468351913'
      var key = DKIMKey.parse( record )

      assert.strictEqual( key.version, 'DKIM1' )
      assert.strictEqual( key.type, 'rsa' )
      assert.strictEqual( key.note, '2048,1452627113,1468351913' )
      assert.strictEqual( key.isTest(), false )
      assert.strictEqual( key.isRevoked(), false )

    })

  })

})

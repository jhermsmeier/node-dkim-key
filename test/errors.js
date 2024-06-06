const assert = require( 'node:assert' )
const DKIMKey = require( '..' )

context( 'DKIMKey', () => {

  context( 'Errors', () => {

    test( 'Empty input', () => {
      assert.throws(() => {
        DKIMKey.parse( '' )
      })
    })

    test( 'Missing version tag', () => {

      assert.throws(() => {
        DKIMKey.parse( 'k=rsa; p=' )
      }, /Missing required version/ )

      assert.throws(() => {
        DKIMKey.parse( 'k=rsa; p=; v=DKIM1; n=version tag has to be first' )
      }, /Missing required version/ )

      assert.throws(() => {
        DKIMKey.parse( 'V=DKIM1; k=rsa; p=; n=tag names are case-sensitive' )
      }, /Missing required version/ )

    })

    test( 'Missing key data tag', () => {
      assert.throws(() => {
        DKIMKey.parse( 'v=DKIM1; k=rsa;' )
      }, /Missing required public key/ )
    })

    test( 'Duplicate tags', () => {
      assert.throws(() => {
        DKIMKey.parse( 'v=DKIM1; v=DKIM2; k=rsa; p=' )
      }, /Invalid duplicate tag/ )
    })

    test( 'Invalid character in value', () => {
      assert.throws(() => {
        DKIMKey.parse( 'v=DKIM1; k=rsa; p=; n=øl' )
      }, /Invalid character in tag value/ )
    })

    test( 'Invalid character in name', () => {
      assert.throws(() => {
        DKIMKey.parse( 'v=DKIM1; k=rsa; p=; øl=n' )
      }, /Invalid character in tag name/ )
    })

    test( 'Invalid base64 data', () => {
      assert.throws(() => {
        DKIMKey.parse( 'v=DKIM1; k=rsa; p=--' )
      }, /Invalid base64/ )
    })

  })

})

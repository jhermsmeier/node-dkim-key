const assert = require( 'node:assert' )
const DKIMKey = require( '..' )

context( 'DKIMKey#toString()', () => {

  test( 'Bare minimum', () => {
    var key = new DKIMKey()
    assert.strictEqual( key.toString(), 'v=DKIM1; k=rsa; p=' )
  })

  test( 'Permissible hashes', () => {

    var key = new DKIMKey({ hashes: [ 'sha1', 'sha256' ] })
    assert.strictEqual( key.toString(), 'v=DKIM1; k=rsa; h=sha1:sha256; p=' )

    var key = new DKIMKey({ hashes: [] })
    assert.strictEqual( key.toString(), 'v=DKIM1; k=rsa; p=' )

  })

  test( 'All the things', () => {

    var key = new DKIMKey({
      version: 'DKIM1',
      type: 'rsa',
      hashes: [ 'sha1', 'sha256' ],
      service: DKIMKey.SERVICE_TYPE.EMAIL,
      flags: [ DKIMKey.FLAG.TEST ],
      note: 'a comment to demonstrate',
      data: 'H3cq33YqxdGMz5J7afRt8oP4v2qYJKXncKv1a/xFtg8=',
      unknownTags: new Map([
        [ 'xx', 'unknown extension' ]
      ]),
    })

    var expected = 'v=DKIM1; k=rsa; h=sha1:sha256; s=email; t=y; p=H3cq33YqxdGMz5J7afRt8oP4v2qYJKXncKv1a/xFtg8=; n=a=20comment=20to=20demonstrate; xx=unknown extension'

    assert.strictEqual( key.toString(), expected )

  })

  test( 'Unicode notes', () => {
    var key = new DKIMKey({ note: '😭' })
    assert.strictEqual( key.toString(), 'v=DKIM1; k=rsa; p=; n==F0=9F=98=AD' )
    assert.strictEqual( DKIMKey.parse( key.toString() ).note, key.note )
  })

})

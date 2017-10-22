let dns = require( 'dns' )
let DKIMKey = require( '..' )
let assert = require( 'assert' )

suite( 'DKIM Key Acceptance', function() {
  
  suite( 'Gmail ARC-Message-Signature', function() {
    
    let selector = 'arc-20160816' 
    let domain = 'google.com'
    let txtDomain = `${selector}._domainkey.${domain}`
    
    test( 'DNS TXT Buffer Output', function(done) {
      dns.resolveTxt(txtDomain, (err, records) => {
        assert.equal(err, null)
        let txtRecord = records.join('')
        let key = DKIMKey.parse( txtRecord )
        assert.ok( key )
        assert.ok(Buffer.isBuffer(key.key))
        done()
      })
    })
    
  })

  suite( 'Mandrill DKIM-Signature', function() {
    
    let selector = 'mandrill' 
    let domain = 'mandrillapp.com'
    let txtDomain = `${selector}._domainkey.${domain}`
    
    test( 'DNS TXT Buffer Output', function(done) {
      dns.resolveTxt(txtDomain, (err, records) => {
        assert.equal(err, null)
        let txtRecord = records.join('')

        let key = DKIMKey.parse( txtRecord )
        assert.ok( key )
        assert.ok(Buffer.isBuffer(key.key))
        done()
      })
    })
    
  })
  
})

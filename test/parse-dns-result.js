var dns = require( 'dns' )
var DKIMKey = require( '..' )
var assert = require( 'assert' )

suite( 'DKIM Key Acceptance', function() {
  
  suite( 'Gmail ARC-Message-Signature', function() {
    
    var selector = 'arc-20160816' 
    var domain = 'google.com'
    var txtDomain = selector + '._domainkey.' + domain
    
    test( 'DNS TXT Buffer Output', function(done) {
      dns.resolveTxt(txtDomain, function(err, records) {
        assert.equal(err, null)
        var txtRecord = records.join('')
        var key = DKIMKey.parse( txtRecord )
        assert.ok( key )
        assert.ok(Buffer.isBuffer(key.key))
        done()
      })
    })
    
  })

  suite( 'Mandrill DKIM-Signature', function() {
    
    var selector = 'mandrill' 
    var domain = 'mandrillapp.com'
    var txtDomain = selector + '._domainkey.' + domain
    
    test( 'DNS TXT Buffer Output', function(done) {
      dns.resolveTxt(txtDomain, function(err, records) {
        assert.equal(err, null)
        var txtRecord = records.join('')

        var key = DKIMKey.parse( txtRecord )
        assert.ok( key )
        assert.ok(Buffer.isBuffer(key.key))
        done()
      })
    })
    
  })
  
})

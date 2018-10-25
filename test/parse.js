var DKIMKey = require( '..' )
var dns = require( 'dns' )
var assert = require( 'assert' )

describe( 'DKIM Key', function() {

  context( 'parse()', function() {

    specify( 'DNS TXT Record', function() {
      var txtRecord = 'k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQs8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbbhzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5OctMEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598HY+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB'
      var key = DKIMKey.parse( txtRecord )
      assert.ok( key )
      assert.ok(Buffer.isBuffer(key.key))
    })

  })

  dns.lookup( 'example.com', ( err, result ) => {

    if( err ) return

    context( 'parse()', function() {

      specify( '20161025 1e100.net', function( done ) {

        var selector = '20161025'
        var domain = '1e100.net'
        var dkimDomain = selector + '._domainkey.' + domain
        var keyData = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoesoDYpDnaUGZFoCElFKAkhbPoqBCfkmz3LqSfdAkye2DpoxlBx+qybWdYXe55mCWPeVUIk10Z/H9uriY4enbpmUM0t3mhgyrxuKwJtFg0YgQ0WGpMKecYjhYkt+pcHy7J11BrYh6lHx7mXf5SxuoOF1B6rG1MTzgBKDQqHsBvfz9xZSsNA5HW41EHu4dxRz/QLvzJYegLac8p6oU7l8O/yaVAse0DpgkVu+adfDV+flDq+nohyt2CJ+XHHdbIpE3cb01wp4Znz05zcYaTJd6WIQuis9sjGpS8sDEhY2gZkJVE2jvk1/mObTsyJuVuORapZnXO740owXe8Pvxq7uQIDAQAB'

        dns.resolveTxt( dkimDomain, ( error, records ) => {
          if( error ) return done( error )
          records = records.map(( record ) => record.join( '' ) )
          console.log( records )
          records = records.map( DKIMKey.parse )
          console.log( records )
          assert.strictEqual( records[0].key.toString( 'base64' ), keyData )
          assert.strictEqual( records[0].type, 'rsa' )
          done()
        })

      })

      specify( '20171004 dialogflow.com', function( done ) {

        var selector = '20171004'
        var domain = 'dialogflow.com'
        var dkimDomain = selector + '._domainkey.' + domain
        var keyData = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzI5iaG0vxFScisTDRt9c/id87RBk8+3XK7WTvX8JhTuMwQGkrEsAVSRwj+RACDikGgNoWKO1ozBtGSSXRbwbkhytOWp2QJ75lAi1U/cNHFGZ5a3Vf7OjCB7/QiO4M0euPXZwfb5ya1OhxSCAReYHXkRzmkSjh5jRtPdhdXMJPkCw7Kcg3gQRkThPJ5FvAOYMlHUox4pXbp6H6VQnMvk8qahEhbxc+mv8zqgpBtwqndVE6BREOgku/GAXf8wcdm4Ns4I7XixTCmC40C9aePGL04cQiFt78hdsEsyWFe3uz0Rh5MTh1Z2m5Dk9FVHb384w1462ue61VVNNzl+LXASXiwIDAQAB'

        dns.resolveTxt( dkimDomain, ( error, records ) => {
          if( error ) return done( error )
          records = records.map(( record ) => record.join( '' ) )
          console.log( records )
          records = records.map( DKIMKey.parse )
          console.log( records )
          assert.strictEqual( records[0].key.toString( 'base64' ), keyData )
          assert.strictEqual( records[0].version, 'DKIM1' )
          assert.strictEqual( records[0].type, 'rsa' )
          done()
        })

      })

    })

  })

})

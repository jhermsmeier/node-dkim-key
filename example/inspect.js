const dns = require( 'node:dns' )
const DKIMKey = require( '..' )
const argv = process.argv.slice( 2 )

if( argv.length < 2 ) {
  console.error( 'Usage: node example/inspect <domain> <selector>' )
  process.exit( 1 )
}

var [ domain, selector ] = argv
var hostname = `${selector}._domainkey.${domain}`

dns.resolveTxt( hostname, function( error, records ) {
  if( error ) return void console.error( error )
  records.map(( record ) => {
    try {
      let txtRecord = record.join( '' )
      let key = DKIMKey.parse( txtRecord )
      console.log( '-'.repeat( 80 ) )
      console.log( txtRecord )
      console.log( '-'.repeat( 80 ) )
      console.log( key )
    } catch( error ){
      console.error( error )
    }
  })
})

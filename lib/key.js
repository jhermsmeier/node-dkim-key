/**
 * Key Constructor
 * @return {Key}
 */
function Key( options ) {

  if( !(this instanceof Key) )
    return new Key( options )

  this.version = null
  this.type = 'rsa-sha256'
  this.flags = null
  this.granularity = null
  this.hash = null
  this.notes = null
  this.service = null
  this.key = null

  var self = this

  if( options != null ) {
    Object.keys( options ).forEach( function( k, v ) {
      if( Key.fields.indexOf( k ) !== -1 ) {
        self[ k ] = options[ k ]
      }
    })
  }

}

Key.fields = [
  'version',
  'type',
  'flags',
  'granularity',
  'hash',
  'notes',
  'service',
  'key',
]

Key.keys = [
  'v', // version
  'k', // type
  't', // flags
  'g', // granularity
  'h', // hash
  'n', // notes
  's', // service
  'p', // key
]

Key.fieldMap = {
  g: 'granularity',
  h: 'hash',
  k: 'type',
  n: 'notes',
  p: 'key',
  s: 'service',
  t: 'flags',
  v: 'version',
}

Key.create = function( options ) {
  return new Key( options )
}

Key.parse = function( value ) {
  return new Key().parse( value )
}

/**
 * Key Prototype
 * @type {Object}
 */
Key.prototype = {

  constructor: Key,

  /**
   * Parse a DKIM key from a String or Buffer
   * @param {Strring|Buffer} input
   * @returns {Key}
   */
  parse( input ) {

    var value = ( input + '' ).replace( /\r\n\s/g, '' )
    var offset = 0
    var assignOffset = -1
    var delimiterOffset = -1
    var field = ''
    var fieldValue = ''

    while( offset < value.length ) {

      if( /\s/.test( value[ offset ] ) ) {
        offset++
        continue
      }

      assignOffset = value.indexOf( '=', offset + 1 )

      field = value.slice( offset, assignOffset )

      if( Key.keys.indexOf( field ) === -1 ) {
        throw new Error( `Unknown field name "${field}"` )
      }

      delimiterOffset = value.indexOf( ';', assignOffset + 1 )

      fieldValue = value.slice( assignOffset + 1, delimiterOffset !== -1 ? delimiterOffset : undefined )

      this[ Key.fieldMap[ field ] ] = field !== 'p' ?
        fieldValue : Buffer.from( fieldValue, 'base64' )

      offset = delimiterOffset !== -1 ?
        delimiterOffset + 1 : value.length

    }

    return this

  },

  toString() {

    var self = this

    return Key.fields.map( function( field, i ) {
      if( typeof self[ field ] === 'string' || typeof self[ field ] === 'number' )
        return Key.keys[ i ] + '=' + self[ field ]
      else if( Array.isArray( self[ field ] ) && self[ field ].length )
        return Key.keys[ i ] + '=' + self[ field ].join( ':' )
      else if( Buffer.isBuffer( self[ field ] ) && self[ field ].length )
        return Key.keys[ i ] + '=' + self[ field ].toString( 'base64' )
    })
    .filter( function( field ) {
      return field != null
    })
    .join( '; ' )

  }

}

// Exports
module.exports = Key

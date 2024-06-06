const quotedPrintable = require( 'dkim-quoted-printable' )

// NOTE: Excludes allowed leading and trailing FWS;
// Tag names should be unfolded and trimmed before
// testing against this pattern
// @see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
const TAG_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_]*$/

// NOTE: Excludes FWS; Values should be unfolded and
// trimmed before testing against this pattern
// @see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
const TAG_VALUE_PATTERN = /^[\x09\x20\x21-\x3A\x3C-\x7E]*$/

// NOTE: Excludes any whitespace; value should be unfolded and
// trimmed before testing against this pattern
// ALPHADIGITPS = (ALPHA / DIGIT / "+" / "/")
// base64string = ALPHADIGITPS *([FWS] ALPHADIGITPS) [ [FWS] "=" [ [FWS] "=" ] ]
const BASE64_PATTERN = /^[a-zA-Z0-9\+\/]+[=]*$/

// String#trim() trims too many characters
// for what is allowed by DKIM (WSP = SP / HTAB)
function trimWhitespace( value ) {
  return value.replace( /^[\x09\x20]+|[\x09\x20]+$/g, '' )
}

class DKIMKey {

  /** @enum {String} Key flags */
  static FLAG = {
    // y  This domain is testing DKIM.  Verifiers MUST NOT treat messages
    //    from Signers in testing mode differently from unsigned email,
    //    even should the signature fail to verify.  Verifiers MAY wish
    //    to track testing mode results to assist the Signer.
    TEST: 'y',
    // s  Any DKIM-Signature header fields using the "i=" tag MUST have
    //    the same domain value on the right-hand side of the "@" in the
    //    "i=" tag and the value of the "d=" tag.  That is, the "i="
    //    domain MUST NOT be a subdomain of "d=".  Use of this flag is
    //    RECOMMENDED unless subdomaining is required.
    STRICT: 's',
  }

  /** @enum {String} Service types */
  static SERVICE_TYPE = {
    ANY: '*',
    EMAIL: 'email',
  }

  /** @enum {String} Key versions */
  static VERSION = {
    DKIM1: 'DKIM1',
  }

  /** @type {String} Key record version. REQUIRED */
  version = 'DKIM1'
  /** @type {String} Public-key type. OPTIONAL, default is "rsa" */
  type = 'rsa'
  /** @type {Array<String>|undefined} Acceptable hash algorithms. OPTIONAL, defaults to allowing all algorithms */
  hashes = undefined
  /** @type {String|undefined} Service type. OPTIONAL, default is "*" */
  service = undefined
  /** @type {Array<String>|undefined} Flags, represented as a colon-separated list of names (plain-text; OPTIONAL, default is no flags set) */
  flags = undefined
  /** @type {String|undefined} Notes. OPTIONAL. */
  note = undefined
  /** @type {String|undefined} [RFC 4870, deprecated in RFC 6376] */
  granularity = undefined
  /** @type {String} Public-key data. REQUIRED. Empty key means that the key has been revoked. */
  data = undefined
  /** @type {Map<String,String>|undefined} Map of unknown tags in the key record */
  unknownTags = undefined

  constructor( options ) {
    if( options != null ) {
      if( options.version ) this.version = options.version
      if( options.hashes ) this.hashes = [].concat( options.hashes )
      if( options.type ) this.type = options.type
      if( options.service ) this.service = options.service
      if( options.flags ) this.flags = [].concat( options.flags )
      if( options.note ) this.note = options.note
      if( options.granularity ) this.granularity = options.granularity
      if( options.data ) {
        this.data = Buffer.isBuffer( options.data )
          ? options.data.toString( 'base64' )
          : options.data
      }
      if( options.unknownTags ) {
        this.unknownTags = Array.isArray( options.unknownTags )
          ? new Map( options.unknownTags )
          : new Map( options.unknownTags.entries() )
      }
    }
  }

  static Error = class DKIMKeyError extends Error {
    constructor( message ) {
      super( message )
    }
  }

  /**
   * Returns `true` if the key should be considered revoked.
   * @return {Boolean}
   */
  isRevoked() {

    if( !this.data || this.data.length == 0 )
      return true

    // Also consider keys to be revoked if there is base64 data,
    // but the resulting value is empty
    var data = Buffer.from( this.data, 'base64' )
      .toString( 'ascii' )

    if( !trimWhitespace( data ) )
      return true

    return false

  }

  /**
   * Returns `true` if the key has the "strict" flag set.
   * @see {DKIMKey.FLAG} for details
   * @return {Boolean}
   */
  isStrict() {
    return this.flags != null
      ? this.flags.includes( DKIMKey.FLAG.STRICT )
      : false
  }

  /**
   * Returns `true` if the key has the "test" flag set.
   * @see {DKIMKey.FLAG} for details
   * @return {Boolean}
   */
  isTest() {
    return this.flags != null
      ? this.flags.includes( DKIMKey.FLAG.TEST )
      : false
  }

  /**
   * Check whether a given hashing algorithm is listed
   * as acceptable by this key record
   * @param {String} hash
   * @returns {Boolean}
   */
  isAcceptableHash( hash ) {
    return this.hashes != null
      ? this.hashes.includes( hash )
      : true
  }

  /**
   * @internal Test whether a tag name contains only valid characters
   * @param {String} value
   * @returns {Boolean}
   */
  static isValidTagName( value ) {
    return TAG_NAME_PATTERN.test( value )
  }

  /**
   * @internal Test whether a tag value contains only valid characters
   * @param {String} value
   * @returns {Boolean}
   */
  static isValidTagValue( value ) {
    return TAG_VALUE_PATTERN.test( value )
  }

  /**
   * @internal Parse a colon (":") separated list
   * @param {String} tagValue
   * @returns {Array<String>}
   */
  static parseColonList( tagValue ) {
    if( !tagValue ) return undefined
    return tagValue.split( /[\x09\x20]*:[\x09\x20]*/g )
  }

  /**
   * @internal Normalize and validate a base64 string
   * @param {String} tagValue
   * @returns {String}
   */
  static normalizeBase64( tagValue ) {

    // Strip all whitespace
    var value = tagValue.replace( /\s+/g, '' )
    if( !value ) return undefined

    if( !BASE64_PATTERN.test( value ) ) {
      throw new DKIMKey.Error( 'Invalid base64 data' )
    }

    return value

  }

  /**
   * Parse a DKIM key record
   * @param {String|Buffer} value
   * @returns {DKIM.Key}
   */
  static parse( value ) {

    if( typeof value != 'string' && !Buffer.isBuffer( value ) )
      throw new TypeError( 'DKIM-Key: Value must be a string or buffer' )

    // Unfold folding whitespace (FWS = [*WSP CRLF] 1*WSP)
    value = String( value ).replace( /[\x09\x20]*\r\n[\x09\x20]/g, '' )
      .replace( /\r\n$/, '' ) // Also strip trailing CRLF

    var offset = 0
    var length = value.length
    var key = new DKIMKey()
    var tags = new Set()
    var isFirstTag = true

    while( offset < length ) {

      let eot = value.indexOf( '=', offset )
      if( eot == -1 ) throw new DKIMKey.Error( 'Missing tag value delimiter' )
      let tagName = trimWhitespace( value.slice( offset, eot ) )

      if( !DKIMKey.isValidTagName( tagName ) ) {
        throw new DKIMKey.Error( 'Invalid character in tag name' )
      }

      offset = eot + 1

      let eon = value.indexOf( ';', offset )
      if( eon == -1 ) eon = length
      let tagValue = trimWhitespace( value.slice( offset, eon ) )

      if( !DKIMKey.isValidTagValue( tagValue ) ) {
        throw new DKIMKey.Error( 'Invalid character in tag value' )
      }

      offset = eon + 1

      // The version tag MUST be the first tag in the record
      // RFC 6376, Section 3.6.1
      if( isFirstTag ) {
        if( tagName != 'v' ) throw new DKIMKey.Error( 'Missing required version tag' )
        isFirstTag = false
      }

      // Tags with duplicate names MUST NOT occur within a single tag-list; if
      // a tag name occurs more than once, the entire tag-list is invalid.
      // @see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
      if( tags.has( tagName ) ) {
        throw new DKIMKey.Error( 'Invalid duplicate tag name' )
      } else {
        tags.add( tagName )
      }

      switch( tagName ) {
        case 'v': key.version = tagValue; break
        case 'h': key.hashes = DKIMKey.parseColonList( tagValue ); break
        case 'k': key.type = tagValue; break
        case 'p': key.data = DKIMKey.normalizeBase64( tagValue ); break
        case 's': key.service = tagValue; break
        case 't': key.flags = DKIMKey.parseColonList( tagValue ); break
        case 'n': key.note = quotedPrintable.decode( tagValue ); break
        case 'g': key.granularity = tagValue; break
        default: // unknown field (ignore, but store)
          key.unknownTags = key.unknownTags ?? new Map()
          key.unknownTags.set( tagName, tagValue )
          break
      }

    }

    if( !tags.has( 'v' ) )
      throw new DKIMKey.Error( 'Missing required version tag' )
    if( !tags.has( 'p' ) )
      throw new DKIMKey.Error( 'Missing required public key data tag' )

    if( key.version !== DKIMKey.VERSION.DKIM1 ) {
      throw new DKIMKey.Error( 'Invalid or unsupported version' )
    }

    return key

  }

  /**
   * Create a JSON-serializable object of the key record
   * @returns {Object}
   */
  toJSON() {

    var value = {}

    value.version = this.version
    value.type = this.type ?? undefined
    value.hashes = this.hashes?.slice() ?? undefined
    value.service = this.service == '*' ? undefined : this.service
    value.flags = this.flags ?? undefined
    value.note = this.note ?? undefined
    value.granularity = this.granularity ?? undefined
    value.data = this.data

    if( this.unknownTags != null && this.unknownTags.size ) {
      value.unknownTags = Array.from( this.unknownTags.entries() )
    }

    return value

  }

  /**
   * Serialize the key record to a string
   * @returns {String}
   */
  toString() {

    var fields = [ `v=${this.version}` ]

    if( this.type )
      fields.push( `k=${this.type}` )
    if( this.hashes && this.hashes.length )
      fields.push( `h=${this.hashes.join( ':' )}` )
    if( this.service && this.service != '*' )
      fields.push( `s=${this.service}` )
    if( this.flags && this.flags.length )
      fields.push( `t=${this.flags.join( ':' )}` )
    if( this.granularity )
      fields.push( `g=${this.granularity}` )
    if( this.data )
      fields.push( `p=${this.data.toString( 'base64' )}` )
    else // Empty key means key has been revoked
      fields.push( 'p=' )
    if( this.note )
      fields.push( `n=${quotedPrintable.encode(this.note)}` )

    if( this.unknownTags != null && this.unknownTags.size != 0 ) {
      for( let [ tagName, tagValue ] of this.unknownTags ) {
        fields.push( `${tagName}=${tagValue}` )
      }
    }

    return fields.join( '; ' )

  }

}

module.exports = DKIMKey

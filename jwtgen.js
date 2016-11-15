#!/usr/bin/env node

'use strict';

var _ = require( 'lodash' );

var fs = require( 'fs' );

var yargs = require( 'yargs' );

var jwt = require( 'jwt-simple' );

var argv = yargs.usage( 'Usage: $0 [options]' )
            
    .demand( 'a' )
    .describe( 'a', 'algorithm' )
    .choices( 'a', [ 'HS256', 'HS384', 'HS512', 'RS256' ] )
    .alias( 'a', 'algorithm' )
    
    .describe( 's', 'secret value for HMAC algorithm' )
    .alias( 's', 'secret' )
    .string( 's' )
    
    .describe( 'p', 'private key file (required for RS256 algorithm)' )
    .alias( 'p', 'private' )
    .string( 'p' )

    .describe( 'c', 'claim in the form [key=value]' )
    .alias( 'c', 'claim' )
    .string( 'c' )

    .describe( 'claims', 'JSON string containing claims' )
    .string( 'claims' )

    .describe( 'h', 'header in the form [key=value]' )
    .alias( 'h', 'header' )
    .string( 'h' )

    .describe( 'headers', 'JSON string containing additional headers' )
    .string( 'headers' )

    .describe( 'i', 'issued at (iat) in seconds from the UNIX epoch' )
    .alias( 'i', 'iat' )
    .default( 'i', Math.floor(Date.now()/1000), 'now' )

    .describe( 'e', 'expiry date in seconds from issued at (iat) time' )
    .alias( 'e', 'exp' )
    .number( 'e ' )

    .describe( 'v', 'verbose output' )
    .alias( 'v', 'verbose' )
    .boolean( 'v' )

    .help( 'help' )
    .argv;


function exitError( message ) {

    yargs.showHelp();

    console.error( message );

    process.exit( 1 );
}

function log( message ) {

    if( argv.v ) {

        console.log( message );
    }
}

function getPrivateKey() {

    return fs.readFileSync( argv.p );
}

function addClaim( claims, key, value ) {

    claims[ key.trim() ] = value.trim();
}

function buildClaims() {

    if( argv.claims ) {

        return JSON.parse( argv.claims );
    }

    var claimsList = [];

    if( _.isArray( argv.c ) ) {

        claimsList = argv.c;
    }
    else {

        claimsList = [ argv.c ];
    }

    var claims = {};

    _.forEach( claimsList, function( claim ) {

        var parts = _.split( claim, '=' );

        if( parts.length !== 2 ) {

            console.error( 'invalid claim: ' + claim );
        }

        claims[ parts[0].trim() ] = parts[1].trim();
    });

    return claims;
}

function buildHeaders() {

    if( argv.headers ) {

        return JSON.parse( argv.headers );
    }

    var headersList = [];

    if( _.isArray( argv.h ) ) {

        headersList = argv.h;
    }
    else if (argv.h) {

        headersList = [ argv.h ];
    }

    var headers = {};

    _.forEach( headersList, function( header ) {

        var parts = _.split( header, '=' );

        if( parts.length !== 2 ) {

            console.error( 'invalid claim: ' + header );
        }

        headers[ parts[0].trim() ] = parts[1].trim();
    });

    return headers;
}

var claims = buildClaims();

if( argv.i < 0 ) {

    claims.iat = Math.floor((Date.now()/1000) + argv.i);
}
else {

    claims.iat = Math.floor( argv.i );
}

if( argv.e ) {

    claims.exp = claims.iat + Math.floor( argv.e );
}

var headers = buildHeaders();

var token;

if( argv.a === 'RS256' ) {

    if( !argv.p ) {

        exitError( 'private key missing' );
    }

    token = jwt.encode( claims, getPrivateKey(), argv.a, { header: headers } );
}
else {

    if( !argv.s ) {

        exitError( 'secret value missing' );
    }

    token = jwt.encode( claims, argv.s, argv.a, { header: headers } );
}

log( 'algorithm: ' + argv.a );

log( '' );

log( 'headers: ' );
log( JSON.stringify( headers, null, 2 ) );

log( '' );

log( 'claims: ' );
log( JSON.stringify( claims, null, 2 ) );

log( '' );

log( 'token:' );
console.log( token );

process.exit( 0 );
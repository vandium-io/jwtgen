#!/usr/bin/env node

'use strict';

const _ = require( 'lodash' );

const yargs = require( 'yargs' );

const jwtBuilder = require( 'jwt-builder' );

const argv = yargs.usage( 'Usage: $0 [options]' )

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

function buildClaims() {

    if( argv.claims ) {

        return JSON.parse( argv.claims );
    }

    let claimsList = [];

    let claims = {};

    if( argv.c ) {

        if( _.isArray( argv.c ) ) {

            claimsList = argv.c;
        }
        else {

            claimsList = [ argv.c ];
        }

        claimsList.forEach( function( claim ) {

            let parts = claim.split( '=' );

            if( parts.length !== 2 ) {

                throw new Error( 'invalid claim: ' + claim );
            }

            try {

                claims[ parts[0].trim() ] = JSON.parse( parts[1].trim() );
            }
            catch( e ) {

                claims[ parts[0].trim() ] = parts[1].trim();
            }
        });
    }

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
    else if( argv.h ) {

        headersList = [ argv.h ];
    }

    var headers = {};

    _.forEach( headersList, function( header ) {

        var parts = _.split( header, '=' );

        if( parts.length !== 2 ) {

            throw new Error( 'invalid header: ' + header );
        }

        headers[ parts[0].trim() ] = parts[1].trim();
    });

    return headers;
}

let builder = jwtBuilder();

try {

    builder.headers( buildHeaders() );

    builder.claims( buildClaims() );
}
catch( err ) {

    return exitError( err.message );
}

builder.iat( argv.i );

if( argv.e ) {

    builder.exp( argv.e );
}

builder.algorithm( argv.a );

if( argv.a === 'RS256' ) {

    if( !argv.p ) {

        return exitError( 'private key missing' );
    }

    builder.privateKeyFromFile( argv.p );
}
else {

    if( !argv.s ) {

        return exitError( 'secret value missing' );
    }

    builder.secret( argv.s );
}

let token = builder.build();

let claims = JSON.parse( new Buffer( token.split( '.' )[1], 'base64' ).toString() );

let headers = JSON.parse( new Buffer( token.split( '.')[0], 'base64' ).toString() );

log( 'algorithm: ' + argv.a );

log( '' );

log( 'claims: ' );
log( JSON.stringify( claims, null, 2 ) );

log( '' );

log( 'headers: ' );
log( JSON.stringify( headers, null, 2 ) );

log( '' );

log( 'token:' );

console.log( token );

process.exit( 0 );

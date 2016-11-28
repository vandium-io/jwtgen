'use strict';
/* jshint expr: true */

const expect = require( 'chai' ).expect;

const proxyquire = require( 'proxyquire' ).noCallThru();

const sinon = require( 'sinon' );

const MODULE_PATH = process.env.PWD + '/bin/jwtgen';

const SAMPLE_TOKEN =
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' +
    'eyJpYXQiOjE0Nzk0MjAyNjh9.' +
    'fvnfV_5cKYcxCGiXSithIVdy-ajBUTssBXe6ge05d5o';

function decodeToken( token ) {

    let claims = JSON.parse( new Buffer( token.split( '.' )[1], 'base64' ).toString() );

    let headers = JSON.parse( new Buffer( token.split( '.')[0], 'base64' ).toString() );

    return {

        claims,
        headers
    };
}

describe( MODULE_PATH, function() {

    let yargsStub;

    let processExitStub;

    let consoleLogStub;

    let consoleErrorStub;

    beforeEach( function() {

        processExitStub = sinon.stub( process, 'exit' );

        yargsStub = {};

        yargsStub.usage = sinon.stub().returns( yargsStub );
        yargsStub.command = sinon.stub().returns( yargsStub );
        yargsStub.strict = sinon.stub().returns( yargsStub );
        yargsStub.demand = sinon.stub().returns( yargsStub );
        yargsStub.describe = sinon.stub().returns( yargsStub );
        yargsStub.choices = sinon.stub().returns( yargsStub );
        yargsStub.alias = sinon.stub().returns( yargsStub );
        yargsStub.string = sinon.stub().returns( yargsStub );
        yargsStub.number = sinon.stub().returns( yargsStub );
        yargsStub.boolean = sinon.stub().returns( yargsStub );
        yargsStub.default = sinon.stub().returns( yargsStub );
        yargsStub.help = sinon.stub().returns( yargsStub );
        yargsStub.showHelp = sinon.stub()
    });

    it( 'normal operation', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers ).to.eql( { typ: 'JWT', alg: 'HS256' } );
        expect( token.claims.iat ).to.equal( Math.floor( Date.now() / 1000 ) );
    });

    it( 'expiry date', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            e: 3600
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.exp - token.claims.iat ).to.equal( 3600 );
    });

    it( 'RS256', function() {

        yargsStub.argv = {

            a: 'RS256',
            p: '/path/to/a/file'
        };

        let buildStub = sinon.stub().returns( SAMPLE_TOKEN );
        let privateKeyFromPathStub = sinon.stub();

        sinon.stub( console, 'log' ); // makes output more elegant

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub,
            'jwt-builder': sinon.stub().returns({

                headers: sinon.stub(),
                claims: sinon.stub(),
                iat: sinon.stub(),
                algorithm: sinon.stub(),
                privateKeyFromPath: privateKeyFromPathStub,
                build: buildStub
            })
        });

        console.log.restore();

        expect( privateKeyFromPathStub.withArgs( '/path/to/a/file' ).calledOnce ).to.be.true;
        expect( buildStub.calledOnce ).to.be.true;
    });

    it( 'error: RS256 with no private key', function() {

        yargsStub.argv = {

            a: 'RS256'
        };

        let buildStub = sinon.stub().returns( SAMPLE_TOKEN );

        sinon.stub( console, 'log' ); // makes output more elegant
        let consoleErrorStub = sinon.stub( console, 'error' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub,
            'jwt-builder': sinon.stub().returns({

                headers: sinon.stub(),
                claims: sinon.stub(),
                iat: sinon.stub(),
                algorithm: sinon.stub(),
                privateKeyFromPath: sinon.stub(),
                build: buildStub
            })
        });

        console.log.restore();
        console.error.restore();

        expect( consoleErrorStub.withArgs( 'private key missing' ).calledOnce ).to.be.true;
        expect( yargsStub.showHelp.calledOnce ).to.be.true;
        expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
    });

    it( 'error: no secret', function() {

        yargsStub.argv = {

            a: 'HS256'
        };

        try {

            sinon.stub( console, 'error' );

            proxyquire( MODULE_PATH, {

                'yargs': yargsStub
            });

            throw new Error( 'error should have been thrown when secret was not supplied' );
        }
        catch( err ) {

            console.error.restore();

            expect( err.name ).to.equal( 'Error' );
            expect( err.message ).to.equal( 'missing secret' );
            expect( yargsStub.showHelp.calledOnce ).to.be.true;
            expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
        }
    });

    it( 'verbose operation', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            v: {}
        };

        consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        expect( consoleLogStub.callCount ).to.equal( 10 );
    });

    it( 'single claim', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            c: 'iss=user123'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.iss ).to.equal( 'user123' );
    });

    it( 'array of claims', function(){

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            c: [ 'iss=user123', 'nonce=random' ]
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.iss ).to.equal( 'user123' );
        expect( token.claims.nonce ).to.equal( 'random' );
    });

    it( 'JSON object of claims', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            claims: JSON.stringify( { iss: 'user123' } )
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.iss ).to.equal( 'user123' );
    });

    it( 'error: invalid claim', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            c: 'noEqualsSign'
        };

        try {

            sinon.stub( console, 'error' );

            proxyquire( MODULE_PATH, {

                'yargs': yargsStub
            });

            throw new Error( 'error should have been thrown when the invalid claim could not be parsed' );
        }
        catch( err ) {

            console.error.restore();

            expect( err.name ).to.equal( 'TypeError' );
            expect( err.message ).to.equal( "Cannot read property 'trim' of undefined" );
            expect( yargsStub.showHelp.calledOnce ).to.be.true;
            expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
        }
    });

    it( 'single header', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: 'kid=2016-11-17'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers.kid ).to.equal( '2016-11-17' );
    });

    it( 'array of headers', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: [ 'kid=2016-11-17', 'otherHeader=somethingElse' ]
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers.kid ).to.equal( '2016-11-17' );
        expect( token.headers.otherHeader ).to.equal( 'somethingElse' );
    });

    it( 'JSON object of headers', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            headers: JSON.stringify( { kid: '2016-11-17' } )
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( MODULE_PATH, {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers.kid ).to.equal( '2016-11-17' );
    });

    it( 'error: invalid header', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: 'noEqualsSign'
        };

        try {

            sinon.stub( console, 'error' ); // makes output more elegant

            proxyquire( MODULE_PATH, {

                'yargs': yargsStub
            });

            throw new Error( 'error should have been thrown when the invalid header could not be parsed' );
        }
        catch( err ) {

            console.error.restore();

            expect( err.name ).to.equal( 'TypeError' );
            expect( err.message ).to.equal( "Cannot read property 'trim' of undefined" );
            expect( yargsStub.showHelp.calledOnce ).to.be.true;
            expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
        }
    });

    afterEach( function() {

        process.exit.restore();

        if( console.log.restore ) {

            console.log.restore();
        }

        if( console.error.restore ){

            console.error.restore();
        }
    });
});

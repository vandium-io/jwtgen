'use strict';
/* jshint expr: true */

const expect = require( 'chai' ).expect;

const proxyquire = require( 'proxyquire' ).noCallThru();

const sinon = require( 'sinon' );

const appRoot = require( 'app-root-path' );

function decodeToken( token ) {

    let claims = JSON.parse( new Buffer( token.split( '.' )[1], 'base64' ).toString() );

    let headers = JSON.parse( new Buffer( token.split( '.')[0], 'base64' ).toString() );

    return {

        claims,
        headers
    };
}

describe( 'bin/jwtgen', function() {

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

        proxyquire( '../../bin/jwtgen', {

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

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.exp - token.claims.iat ).to.equal( 3600 );
    });

    it( 'RS256', function() {

        yargsStub.argv = {

            a: 'RS256',
            p: appRoot + '/test/bin/assets/key.pem'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers ).to.eql( { typ: 'JWT', alg: 'RS256' } );
        expect( token.claims.iat ).to.equal( Math.floor( Date.now() / 1000 ) );
    });

    it( 'error: RS256 with no private key', function() {

        yargsStub.argv = {

            a: 'RS256'
        };

        let consoleErrorStub = sinon.stub( console, 'error' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.error.restore();

        expect( consoleErrorStub.withArgs( 'private key missing' ).calledOnce ).to.be.true;
        expect( yargsStub.showHelp.calledOnce ).to.be.true;
        expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
    });

    it( 'error: no secret', function() {

        yargsStub.argv = {

            a: 'HS256'
        };

        let consoleErrorStub = sinon.stub( console, 'error' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.error.restore();

        expect( consoleErrorStub.withArgs( 'secret value missing' ).calledOnce ).to.be.true;
        expect( yargsStub.showHelp.calledOnce ).to.be.true;
        expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
    });

    it( 'verbose operation', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            v: {}
        };

        consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

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

        proxyquire( '../../bin/jwtgen', {

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

        proxyquire( '../../bin/jwtgen', {

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

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.iss ).to.equal( 'user123' );
    });

    it( 'claim that is an array', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            c: 'roles=["ROLE_ADMIN","ROLE_USER"]'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.roles ).to.eql( [ "ROLE_ADMIN", "ROLE_USER" ] );
    });

    it( 'claim that is an object', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            c: 'roles={"type":"ROLE_ADMIN","name":"myRole"}'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.claims.roles ).to.eql( { "type": "ROLE_ADMIN", "name": "myRole" } );
    });

    it( 'error: invalid claim', function() {

        let claim = 'noEqualsSign';

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            c: claim
        };

        let consoleErrorStub = sinon.stub( console, 'error' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.error.restore();

        expect( consoleErrorStub.withArgs( 'invalid claim: ' + claim ).calledOnce ).to.be.true;
        expect( yargsStub.showHelp.calledOnce ).to.be.true;
        expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
    });

    it( 'single header', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: 'kid=2016-11-17'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

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

        proxyquire( '../../bin/jwtgen', {

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

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers.kid ).to.equal( '2016-11-17' );
    });

    it( 'header that is an array', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: 'roles=["ROLE_ADMIN","ROLE_USER"]'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers.roles ).to.eql( [ "ROLE_ADMIN", "ROLE_USER" ] );
    });

    it( 'claim that is an object', function() {

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: 'roles={"type":"ROLE_ADMIN","name":"myRole"}'
        };

        let consoleLogStub = sinon.stub( console, 'log' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.log.restore();

        let token = decodeToken( consoleLogStub.firstCall.args[ 0 ] );

        expect( token.headers.roles ).to.eql( { "type": "ROLE_ADMIN", "name": "myRole" } );
    });

    it( 'error: invalid header', function() {

        let header = 'noEqualsSign';

        yargsStub.argv = {

            a: 'HS256',
            s: 'my-secret',
            h: header
        };

        let consoleErrorStub = sinon.stub( console, 'error' );

        proxyquire( '../../bin/jwtgen', {

            'yargs': yargsStub
        });

        console.error.restore();

        expect( consoleErrorStub.withArgs( 'invalid header: ' + header ).calledOnce ).to.be.true;
        expect( yargsStub.showHelp.calledOnce ).to.be.true;
        expect( processExitStub.withArgs( 1 ).calledOnce ).to.be.true;
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

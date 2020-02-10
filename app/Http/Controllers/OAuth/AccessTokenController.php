<?php 

namespace App\Http\Controllers\OAuth;

use GuzzleHttp\Exception\ClientException;
use Laravel\Passport\Http\Controllers\AccessTokenController as PassportAccessTokenController;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response as Psr7Response;

class AccessTokenController extends PassportAccessTokenController
{
    /**
     * Authorize a client to access the user's account.
     *
     * @param  ServerRequestInterface $request
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function issueToken(ServerRequestInterface $request)
    {
        dd($request);
        try {
            return $this->server->respondToAccessTokenRequest($request, new Psr7Response);
        } catch (ClientException $exception) {
            dd($exception);
            $error = json_decode($exception->getResponse()->getBody());

            throw OAuthServerException::invalidRequest('access_token', object_get($error, 'error.message'));
        } catch (\Exception $exception) {
            dd($exception);
        }
    }
}
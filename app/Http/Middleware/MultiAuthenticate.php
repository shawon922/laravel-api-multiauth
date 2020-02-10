<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use SMartins\PassportMultiauth\Http\Middleware\MultiAuthenticate as Middleware;
use Illuminate\Support\Facades\Auth as AuthFacade;
use SMartins\PassportMultiauth\Facades\ServerRequest;
use SMartins\PassportMultiauth\Config\AuthConfigHelper;

class MultiAuthenticate extends Middleware
{
    /**
     * Handle an incoming request. Authenticates the guard from access token
     * used on request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @param string[] ...$guards
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SMartins\PassportMultiauth\Exceptions\MissingConfigException
     */
    public function handle($request, Closure $next, ...$guards)
    {
        // If don't has any guard follow the flow
        if (empty($guards)) {
            $this->authenticate($request, $guards);

            // Stop laravel from checking for a token if session is not set
            return $next($request);
        }

        $psrRequest = ServerRequest::createRequest($request);

        try {
            $psrRequest = $this->server->validateAuthenticatedRequest($psrRequest);

            if (! ($accessToken = $this->getAccessTokenFromRequest($psrRequest))) {
                throw new AuthenticationException('You are not authenticated.', $guards);
            }

            $guard = $this->getTokenGuard($accessToken, $guards);

            if (empty($guard)) {
                throw new AuthenticationException('You are not authenticated.', $guards);
            }

            // At this point, the authentication will be done by Laravel Passport default driver.
            $this->authenticate($request, $guard);

            $guardsModels = $this->getGuardsModels($guards);

            // The laravel passport will define the logged user on request.
            // The returned model can be anywhere, depending on the guard.
            $user = $request->user();

            // But we need check if the user logged has the correct guard.
            $request->setUserResolver(function ($guard) use ($user, $guardsModels) {
                // If don't exists any guard on $request->user() parameter, the
                // default user will be returned.
                // If has the guard on guards passed on middleware and the model
                // instance are the same on an guard.
                if (! $guard || (isset($guardsModels[$guard]) && $user instanceof $guardsModels[$guard])) {
                    return $user;
                }

                return null;
            });

            // After it, we'll change the passport driver behavior to get the
            // authenticated user. It'll change on methods like Auth::user(),
            // Auth::guard('company')->user(), Auth::check().
            AuthFacade::extend(
                'passport',
                function ($app, $name, array $config) use ($request) {
                    $providerGuard = AuthConfigHelper::getProviderGuard($config['provider']);
                    return tap($this->makeGuard($request, $providerGuard), function ($guard) {
                        Application::getInstance()->refresh('request', $guard, 'setRequest');
                    });
                }
            );
            AuthFacade::clearGuardsCache();
        } catch (OAuthServerException $e) {
            // If has an OAuthServerException check if has unit tests and fake
            // user authenticated.
            if (($user = PassportMultiauth::userActing()) &&
                $this->canBeAuthenticated($user, $guards)
            ) {
                return $next($request);
            }

            // @todo Check if it's the best way to handle with OAuthServerException
            throw new AuthenticationException('You are not authenticated.', $guards);
        }

        return $next($request);
    }
}

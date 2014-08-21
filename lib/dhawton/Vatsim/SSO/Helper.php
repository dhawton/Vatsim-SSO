<?php
/*
 * This file is part of dhawton\Vatsim\SSO
 *
 * Copyright (c) 2007 Andy Smith
 * Copyright (c) 2014 Daniel A. Hawton
 *
 * For full copyright information, please see the LICENSE file that was distributed with the source
 */

namespace dhawton\Vatsim\SSO;
use \dhawton\OAuth;

class Helper
{
    public $version = "1.0.0";

    // Location of the VATSIM SSO, to stick with convention, require via constructor
    private $base = null;

    // Directory path for OAuth API, require via constructor
    private $apiLoc = null;

    // Location for login token requests, require via constructor
    private $loginTokenLoc = null;

    // Location for user data queries, require via constructor
    private $userDataQueryLoc = null;

    // Location for redirect, require via constructor
    private $redirectLoginLoc = null;

    // Set default output format, VATSIM likes JSON
    private $format = "json";

    // cURL timeout for requests
    private $curlTimeout = 15;

    // Error array
    private $error = array(
        "type" => null,
        "message" => null,
        "code" => null
    );

    // Signature
    private $signature = null;

    // Token, instance of Token
    private $token = null;

    // Consumer credentials, instance of \dhawton\OAuth\Consumer
    private $consumer = null;

    /**
     * Configure Helper class
     *
     * @param $base             URL Base
     * @param $apiLoc           Location of API
     * @param $loginTokenLoc    Location for login tokens
     * @param $userDataQueryLoc Location to grab User Data from
     * @param $redirectLoc      Location to redirect users to after login
     * @param $key              Our organization key
     * @param null $secret      Secret key, only valid for HMAC
     * @param null $signature   RSA|HMAC
     * @param null $privateKey  OpenSSL RSA Key (only valid if using RSA)
     */
    public function __construct($base, $apiLoc, $loginTokenLoc, $userDataQueryLoc, $redirectLoc, $key, $secret = null, $signature = null, $privateKey = null)
    {
        $this->base = $base;
        $this->loginTokenLoc = $loginTokenLoc;
        $this->userDataQueryLoc = $userDataQueryLoc;
        $this->redirectLoc = $redirectLoc;
        $this->consumer = new OAuth\Consumer($key, $secret);
        if ($signature)
            $this->signature($signature, $privateKey);
    }

    /**
     * Obtain user login details from SSO
     *
     * @param $tokenKey
     * @param $tokenSecret
     * @param $tokenVerifier
     *
     * @return object|bool
     */
    public function checkLogin($tokenKey, $tokenSecret, $tokenVerifier)
    {
        $this->token = new OAuth\Consumer($tokenKey, $tokenSecret);

        $returnUrl = $this->base . $this->apiLoc . $this->userDataQueryLoc . $this->format . "/";
        $request = OAuth\Request::fromConsumerAndToken($this->consumer, $this->token, "POST", $returnUrl, array(
            'oauth_token' => $tokenKey,
            'oauth_verifier' => $tokenVerifier
        ));

        $request->signRequest($this->signature, $this->consumer, $this->token);

        $response = $this->curlRequest($returnUrl, $request->toPostData());

        if ($response) {
            $sso = $this->responseFormat($response);
            if ($sso->request->result == "success") {
                $this->token = false;
                return $sso;
            } else {
                $this->error = array(
                    "type" => "oauth_response",
                    "code" => null,
                    "message" => $sso->request->message
                );

                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Processes curl request
     *
     * @param $url
     * @param $requestString
     *
     * @return bool|mixed
     */
    private function curlRequest($url, $requestString)
    {
        $curlhandler = curl_init();
        curl_setopt_array($curlhandler, array(
            CURLOPT_URL => $url,
            CURLOPT_USERAGENT => "dhawton\Vatsim\SSO\Helper {$this->version}",
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_TIMEOUT => $this->curlTimeout,
            CURLOPT_POST => 1,
            CURLOPT_POSTFIELDS => $requestString
        ));

        $response = curl_exec($curlhandler);

        if (!$response) {
            $this->error = array(
                "type" => "curlRequest",
                "code" => curl_errno($curlhandler),
                "message" => curl_error($curlhandler)
            );

            return false;
        } else {
            return $response;
        }
    }

    /**
     * Set or return format type.  Accepted formats: xml, json
     *
     * @param null $change      null|json|xml
     *
     * @return string           format or null
     * @throws \dhawton\OAuth\OAuthException
     */
    public function format($change=null)
    {
        if (!$change) {
            return $this->format;
        }

        $change = strtolower($change);

        switch($change) {
            case "":
                $this->format = "json";
                break;
            case "json":
            case "xml":
                $this->format = $change;
                break;
            default:
                throw new OAuth\OAuthException("Unknown change type passed.  Valid format types: json, xml");
                break;
        }

        return $this->format;
    }

    /**
     * Request login token from VATSIM
     *
     * @param null $redirectUrl
     * @param bool $allowSuspended
     * @param bool $allowInactive
     *
     * @return object|bool
     */
    public function requestToken($redirectUrl = null, $allowSuspended = false, $allowInactive = false)
    {
        if (!$this->signature) return false;

        if (!$redirectUrl) {
            $scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 'on') ? 'http' : 'https';
            $redirectUrl = $scheme . "://" . $_SERVER['SERVER_NAME'] . ':' . $_SERVER['SERVER_PORT'] .
                $_SERVER['PHP_SELF'];
        }

        $tokenUrl = $this->base . $this->apiLoc . $this->loginTokenLoc . $this->format . '/';

        $req = OAuth\Request::fromConsumerAndToken($this->consumer, null, "POST", $tokenUrl, array(
            'oauth_callback' => $redirectUrl,
            'oauth_allow_suspended' => ($allowSuspended) ? true : false,
            'oauth_allow_inactive' => ($allowInactive) ? true : false
        ));

        $req->signRequest($this->signature, $this->consumer, false);

        $response = $this->curlRequest($tokenUrl, $req->toPostData());

        if ($response) {
            $sso = $this->responseFormat($response);

            if ($sso->request->result == "success") {
                if ($sso->token->oauth_callback_confirmed == "true") {
                    $this->token = new OAuth\Consumer($sso->token->oauth_token, $sso->token->oauth_token_secret);

                    return $sso;
                } else {
                    $this->error = array(
                        'type' => 'callback_confirm',
                        'code' => null,
                        'message' => 'Callback confirmation flag is missing or protocol mismatch'
                    );

                    return false;
                }
            } else {
                $this->error = array(
                    'type' => 'oauth_response',
                    'code' => null,
                    'message' => $sso->request->message
                );

                return false;
            }
        }

        return false;
    }

    /**
     * Parse response into a known format
     *
     * @param $response
     *
     * @return mixed|\SimpleXMLElement
     */
    private function responseFormat($response) {
        if ($this->format == "xml") {
            return new \SimpleXMLElement($response);
        } else {
            return json_decode($response);
        }
    }

    /**
     * After we get token, redirect user to VATSIM SSO Login via Header Location redirect
     *
     * @return bool
     */
    public function sendToVatsim()
    {
        if (!$this->token)
            return false;

        header("Location: " . $this->base . $this->redirectLoginLoc . $this->token->key);
        exit();
    }

    /**
     * Setup the signing method for encryption of signature
     *
     * @param $type             Encryption algorithm: HMAC[_SHA1]|RSA[_SHA1]
     * @param null $privateKey  Only used for RSA
     *
     * @return bool             true if usable
     */
    public function signature($type, $privateKey = null)
    {
        $type = strtoupper($type);

        if ($type == "HMAC" || $type == "HMAC-SHA1") {
            $this->signature = new OAuth\SignatureMethods\HMAC_SHA1();

            return true;
        }

        if ($type=="RSA" || $type == "RSA-SHA1") {
            if (!$privateKey) return false;

            $this->signature = new OAuth\SignatureMethods\RSA_SHA1($privateKey);
            return true;
        }

        return false;
    }

    public function error()
    {
        return $this->error;
    }
}
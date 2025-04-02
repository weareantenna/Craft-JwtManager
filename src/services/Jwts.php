<?php
/**
 * JWT Manager for Craft.
 *
 * @author    Hubert Prein
 * @copyright Copyright (c) 2018
 * @package   JwtManager
 * @since     1.0.0
 */

namespace hubertprein\jwtmanager\services;

use Craft;
use craft\db\Query;
use craft\elements\User;
use craft\helpers\UrlHelper;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT as JwtEngine;
use hubertprein\jwtmanager\JwtManager;
use hubertprein\jwtmanager\models\Jwt;
use hubertprein\jwtmanager\records\Jwt as JwtRecord;

/**
 * Jwts service.
 */
class Jwts extends Base
{
    // Properties
    // =========================================================================

    /**
     * @var array Created refresh JWTs.
     */
    private array $_createdRefreshJwts = [];

    /**
     * @var string|null Current request user-agent.
     */
    private ?string $_currentUserAgent;

    /**
     * @var string|null Current request device type.
     */
    private ?string $_currentDeviceType;

    /**
     * @var string|null Current request browser type.
     */
    private ?string $_currentBrowserType;

    // Public Methods
    // =========================================================================

    /**
     * Init service.
     *
     * @return void
     */
    public function init(): void
    {
        parent::init();

        // Get request information
        $this->_currentUserAgent = JwtManager::$plugin->mobileDetect->getUserAgent();
        $this->_currentDeviceType = JwtManager::$plugin->mobileDetect->getDeviceType();
        $this->_currentBrowserType = JwtManager::$plugin->mobileDetect->getBrowserType();
    }

    /**
     * Get the token from current request.
     *
     * @return string|null if not found.
     */
    public function getTokenFromRequest(): ?string
    {
        $authorizationHeader = Craft::$app->request->headers->get('authorization');

        if ($authorizationHeader && preg_match('/Bearer\s+(.*)$/i', $authorizationHeader, $matches)) {
            if (!empty($matches[1])) {
                return $matches[1];
            }
        }

        return null;
    }

    /**
     * Validate a token.
     *
     * @param string $token
     * @param string $type  [Optional] Validate for specific type.
     *
     * @return bool
     */
    public function isTokenValid(string $token, string $type = ''): bool
    {
        // Get JWT based on token
        $jwt = $this->getOneJwt($token, $type);

        // Basic checks
        if (!$jwt) {
            $this->setError('The JWT could not be found.');
            return false;
        } elseif (!empty($type) && $jwt->type !== $type) {
            $this->setError('The JWT has an incorrect type.');
            return false;
        }

        // Additional checks, if we'd like to login
        if ($jwt->type === Jwt::TYPE_LOGIN) {
            if (strcmp($jwt->device, $this->_currentDeviceType) !== 0) {
                $this->setError('The JWT is not bound to this device.');
                return false;
            } elseif (strcmp($jwt->browser, $this->_currentBrowserType) !== 0) {
                $this->setError('The JWT is not bound to this device.');
                return false;
            }
        }

        return true;
    }

    /**
     * Checks whether a token is expired.
     *
     * @param string $token
     *
     * @return bool
     */
    public function isTokenExpired(string $token): bool
    {
        try {
            $decodedJwt = JwtEngine::decode($token, $this->secretKey, ['HS256']);
        } catch (\Exception $e) {
            if ($e instanceof ExpiredException) {
                return true;
            }
        }

        return false;
    }

    /**
     * Decode a token and return the payload.
     *
     * @param string $token
     *
     * @return \stdClass|null
     */
    public function getTokenPayload(string $token): ?\stdClass
    {
        try {
            // Attempt to get payload
            $decodedJwt = JwtEngine::decode($token, $this->secretKey, ['HS256']);

            // Do we have any data?
            if (isset($decodedJwt->data) && !empty($decodedJwt->data)) {
                // Parse the payload to an object, if it's a valid json string.
                if (is_string($decodedJwt->data)) {
                    $jsonPayload = json_decode($decodedJwt->data);
                    return $jsonPayload ? $jsonPayload : null;
                }
                return $decodedJwt->data;
            }

            // Uh oh..
            $this->setError('The JWT has no data available.');
        } catch (\Exception $e) {
            // Unexpected value, verification failed or expired
            $this->setError($e->getMessage());
        }

        return null;
    }

    /**
     * Get all JWTs.
     *
     * @param int|null $limit
     * @param int|null $offset
     *
     * @return array
     */
    public function getAllJwts(?int $limit = null, ?int $offset = null): array
    {
        $jwts = [];
        foreach ($this->_createJwtQuery()->limit($limit)->offset($offset)->all() as $record) {
            $jwts[] = new Jwt($record);
        }

        return $jwts;
    }

    /**
     * Get total JWTs.
     *
     * @return int
     */
    public function getTotalJwts(): int
    {
        return $this->_createJwtQuery()->count();
    }

    /**
     * Get a JWT.
     *
     * @param array $params DB columns and values.
     *
     * @return Jwt|null
     */
    public function getJwtBy(array $params): ?Jwt
    {
        $record = $this->_createJwtQuery()->where($params)->one();

        return $record ? new Jwt($record) : null;
    }

    /**
     * Get a JWT by it's ID.
     *
     * @param int $id
     *
     * @return Jwt|null
     */
    public function getJwtById(int $id): ?Jwt
    {
        $record = $this->_createJwtQuery()
            ->where(['jwts.id' => $id])
            ->one();

        return $record ? new Jwt($record) : null;
    }

    /**
     * Get a JWT.
     *
     * @param string $token
     * @param string $type  [Optional] Specific type.
     *
     * @return Jwt|null
     */
    public function getOneJwt(string $token, string $type = ''): ?Jwt
    {
        // Set search params
        $params = [
            'token' => $token,
        ];

        // Specific type?
        if (!empty($type)) {
            $params['type'] = $type;
        }

        return $this->getJwtBy($params);
    }

    /**
     * Get a JWT for a user.
     *
     * @param User  $user
     * @param string $type
     * @param bool   $newOnInvalid [Optional] Create new JWT if current is invalid.
     *
     * @return Jwt|null
     */
    public function getOneJwtForUser(User $user, string $type, bool $newOnInvalid = false): ?Jwt
    {
        // Get all JWTs for this user
        $jwts = $this->getAllJwtsForUser($user, $type);

        // Do we have any?
        if (!empty($jwts)) {
            // Get the first one
            $jwt = $jwts[0];

            // Is it valid?
            if ($this->isTokenValid($jwt->token, $type)) {
                return $jwt;
            }

            // Should we create a new one?
            if ($newOnInvalid) {
                return $this->getNewJwtByUser($user, $type);
            }
        }

        return null;
    }

    /**
     * Get all JWTs for a user.
     *
     * @param User  $user
     * @param string $type [Optional] Specific type.
     *
     * @return array
     */
    public function getAllJwtsForUser(User $user, string $type = ''): array
    {
        // Set search params
        $params = [
            'userId' => $user->id,
        ];

        // Specific type?
        if (!empty($type)) {
            $params['type'] = $type;
        }

        // Get all JWTs
        $jwts = [];
        foreach ($this->_createJwtQuery()->where($params)->all() as $record) {
            $jwts[] = new Jwt($record);
        }

        return $jwts;
    }

    /**
     * Get a new JWT.
     *
     * @param string $type
     * @param array  $contents
     *
     * @return Jwt|null
     */
    public function getNewJwt(string $type, array $contents): ?Jwt
    {
        // Create new JWT
        $jwt = new Jwt();
        $jwt->type = $type;
        $jwt->device = $this->_currentDeviceType;
        $jwt->browser = $this->_currentBrowserType;
        $jwt->contents = $contents;

        // Save it
        if ($this->saveJwt($jwt)) {
            return $jwt;
        }

        return null;
    }

    /**
     * Get a new JWT for a user.
     *
     * @param User  $user
     * @param string $type
     * @param array  $contents [Optional] Additional contents.
     *
     * @return Jwt|null
     */
    public function getNewJwtByUser(User $user, string $type, array $contents = []): ?Jwt
    {
        // Add user ID to contents
        $contents['userId'] = $user->id;

        return $this->getNewJwt($type, $contents);
    }

    /**
     * Get a new JWT for a user ID.
     *
     * @param int    $userId
     * @param string $type
     * @param array  $contents [Optional] Additional contents.
     *
     * @return Jwt|null
     */
    public function getNewJwtByUserId(int $userId, string $type, array $contents = []): ?Jwt
    {
        // Add user ID to contents
        $contents['userId'] = $userId;

        return $this->getNewJwt($type, $contents);
    }

    /**
     * Get created refresh token by JWT.
     *
     * @param Jwt $jwt
     *
     * @return Jwt|null
     */
    public function getCreatedRefreshTokenByJwt(Jwt $jwt): ?Jwt
    {
        return $this->_createdRefreshJwts[$jwt->id] ?? null;
    }

    /**
     * Save a JWT.
     *
     * @param Jwt $jwt
     *
     * @return bool
     */
    public function saveJwt(Jwt $jwt): bool
    {
        // Create token
        $jwt->token = $this->_createToken($jwt);

        // Save record
        $record = new JwtRecord();
        $record->id = $jwt->id;
        $record->userId = $jwt->userId;
        $record->type = $jwt->type;
        $record->token = $jwt->token;
        $record->device = $jwt->device;
        $record->browser = $jwt->browser;
        $record->contents = $jwt->contents;
        $record->expiryDate = $jwt->expiryDate;
        $record->lastUsedDate = $jwt->lastUsedDate;
        $record->dateCreated = $jwt->dateCreated;
        $record->dateUpdated = $jwt->dateUpdated;

        if ($record->save()) {
            $jwt->id = $record->id;
            return true;
        }

        return false;
    }

    /**
     * Refresh a JWT.
     *
     * @param Jwt $jwt
     *
     * @return bool
     */
    public function refreshJwt(Jwt $jwt): bool
    {
        // Create new token
        $jwt->token = $this->_createToken($jwt);

        // Save record
        $record = JwtRecord::findOne(['id' => $jwt->id]);
        if ($record) {
            $record->token = $jwt->token;
            $record->dateUpdated = $jwt->dateUpdated;

            return $record->save();
        }

        return false;
    }

    /**
     * Update JWT usage.
     *
     * @param Jwt $jwt
     *
     * @return bool
     */
    public function updateJwtUsage(Jwt $jwt): bool
    {
        // Save record
        $record = JwtRecord::findOne(['id' => $jwt->id]);
        if ($record) {
            $record->lastUsedDate = $jwt->lastUsedDate;
            $record->dateUpdated = $jwt->dateUpdated;

            return $record->save();
        }

        return false;
    }

    /**
     * Delete JWTs by params.
     *
     * @param array $params
     *
     * @return bool
     */
    public function deleteJwtBy(array $params): bool
    {
        // Get records
        $records = JwtRecord::findAll($params);

        // Delete them
        foreach ($records as $record) {
            if (!$record->delete()) {
                return false;
            }
        }

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Create a token.
     *
     * @param Jwt $jwt
     *
     * @return string
     */
    private function _createToken(Jwt $jwt): string
    {
        // Create payload
        $payload = [
            'iss' => UrlHelper::siteUrl(),
            'aud' => UrlHelper::siteUrl(),
            'iat' => time(),
            'exp' => $jwt->expiryDate->getTimestamp(),
            'data' => json_encode($jwt->contents),
        ];

        // Create token
        return JwtEngine::encode($payload, $this->secretKey, 'HS256');
    }

    /**
     * Create JWT query.
     *
     * @return Query
     */
    private function _createJwtQuery(): Query
    {
        return (new Query())
            ->select('jwts.*')
            ->from('{{%jwts}} jwts');
    }
}

<?php
/**
 * JWT Manager for Craft.
 *
 * @author    Hubert Prein
 * @copyright Copyright (c) 2018
 * @package   JwtManager
 * @since     1.0.0
 */

namespace hubertprein\jwtmanager\twigextensions;

use hubertprein\jwtmanager\JwtManager;
use hubertprein\jwtmanager\variables\JwtManagerVariable;
use Twig\Extension\AbstractExtension;

/**
 * JwtManager Twig Extension.
 */
class JwtManagerTwigExtension extends AbstractExtension
{
    /**
     * Return our Twig Extension name.
     *
     * @return string
     */
    public function getName(): string
    {
        return 'JWT Manager';
    }

    /**
     * @inheritdoc
     */
    public function getGlobals(): array
    {
        return ['jwtManager' => new JwtManagerVariable()];
    }
}

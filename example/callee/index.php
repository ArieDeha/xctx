<?php
/**
 * xctx example — PHP Callee Router (port 8082)
 * Run: (inside example/callee)  composer install && composer run start
 */

declare(strict_types=1);

// Composer autoload for 3rd-party deps
require __DIR__ . '/vendor/autoload.php';

// Delegate everything to main.php (our front controller)
require __DIR__ . '/main.php';

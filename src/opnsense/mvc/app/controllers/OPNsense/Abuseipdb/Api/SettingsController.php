<?php

/*
 * Copyright (C) 2026 Kai Schlestein
 * All rights reserved. BSD 2-Clause.
 */

namespace OPNsense\Abuseipdb\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'abuseipdb';
    protected static $internalModelClass = 'OPNsense\\Abuseipdb\\Abuseipdb';
}

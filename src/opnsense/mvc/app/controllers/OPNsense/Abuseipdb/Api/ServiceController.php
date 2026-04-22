<?php

/*
 * Copyright (C) 2026 Kai Voss / IT-Service NF
 * All rights reserved. BSD 2-Clause.
 */

namespace OPNsense\Abuseipdb\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = 'OPNsense\\Abuseipdb\\Abuseipdb';
    protected static $internalServiceTemplate = 'OPNsense/Abuseipdb';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'abuseipdb';

    /**
     * Trigger an ad-hoc blacklist download.
     */
    public function downloadAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $output = trim($backend->configdRun('abuseipdb download'));
            return ['status' => 'ok', 'output' => $output];
        }
        return ['status' => 'failed', 'message' => 'POST required'];
    }

    /**
     * Test connection to AbuseIPDB using stored API key.
     */
    public function testConnectionAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $output = trim($backend->configdRun('abuseipdb testconnection'));
            return ['status' => 'ok', 'output' => $output];
        }
        return ['status' => 'failed', 'message' => 'POST required'];
    }

    /**
     * Return aggregated statistics (blocked / reported / quota).
     */
    public function statsAction()
    {
        $backend = new Backend();
        $output = trim($backend->configdRun('abuseipdb stats'));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return ['status' => 'ok', 'data' => $data];
    }
}

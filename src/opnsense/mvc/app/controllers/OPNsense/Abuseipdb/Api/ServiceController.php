<?php

/*
 * Copyright (C) 2026 Kai Schlestein
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

    /**
     * Trigger firewall alias + block rule setup. Called after settings save.
     */
    public function setupAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $output = trim($backend->configdRun('abuseipdb setup'));
            return ['status' => 'ok', 'output' => $output];
        }
        return ['status' => 'failed', 'message' => 'POST required'];
    }

    /**
     * Return recent reports as JSON (for the Log tab in the plugin GUI).
     */
    public function reportsAction()
    {
        $limit = (int)($this->request->get('limit', 'int', 100));
        if ($limit < 1) $limit = 100;
        if ($limit > 500) $limit = 500;

        $backend = new Backend();
        $output = trim($backend->configdpRun('abuseipdb reports', [(string)$limit]));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return ['status' => 'ok', 'data' => $data];
    }
}

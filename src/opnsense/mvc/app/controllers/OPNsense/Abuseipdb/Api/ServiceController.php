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

    /**
     * Return the live self-defense block list as JSON.
     */
    public function selfcareListAction()
    {
        $limit = (int)($this->request->get('limit', 'int', 200));
        if ($limit < 1) $limit = 200;
        if ($limit > 1000) $limit = 1000;

        $backend = new Backend();
        $output = trim($backend->configdpRun('abuseipdb selfcare_list', [(string)$limit]));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return $data;
    }

    /**
     * Return the Perma-Block list as JSON.
     */
    public function permabanListAction()
    {
        $limit = (int)($this->request->get('limit', 'int', 500));
        if ($limit < 1) $limit = 500;
        if ($limit > 5000) $limit = 5000;

        $backend = new Backend();
        $output = trim($backend->configdpRun('abuseipdb permaban_list', [(string)$limit]));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return $data;
    }

    /**
     * Add an IP to the Perma-Block list. POST with body {ip,note}.
     * No AbuseIPDB report is submitted — that decision is left to the operator.
     */
    public function permabanAddAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $ip = trim((string)$this->request->getPost('ip', 'striptags', ''));
        $note = trim((string)$this->request->getPost('note', 'striptags', ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'failed', 'message' => 'invalid ip address'];
        }
        // Sanitise note: keep length bounded, strip control chars / commas
        // (they break configd's space-separated argv).
        $note = preg_replace('/[^A-Za-z0-9 _\-\.\:]/', '', $note);
        $note = substr($note ?: '', 0, 200);
        $args = [$ip, 'manual', $note !== '' ? $note : '-'];
        $backend = new Backend();
        $output = trim($backend->configdpRun('abuseipdb permaban_add', $args));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return $data;
    }

    /**
     * Remove an IP from the Perma-Block list. POST with body {ip}.
     */
    public function permabanRemoveAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $ip = trim((string)$this->request->getPost('ip', 'striptags', ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'failed', 'message' => 'invalid ip address'];
        }
        $backend = new Backend();
        $output = trim($backend->configdpRun('abuseipdb permaban_remove', [$ip]));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return $data;
    }

    /**
     * Trigger an ad-hoc auto-promote scan.
     */
    public function permabanPromoteAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $backend = new Backend();
        $output = trim($backend->configdRun('abuseipdb permaban_scan'));
        $data = json_decode($output, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'raw' => $output];
        }
        return $data;
    }
}

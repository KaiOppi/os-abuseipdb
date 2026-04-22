<?php

/*
 * Copyright (C) 2026 Kai Voss / IT-Service NF
 * All rights reserved. BSD 2-Clause.
 */

namespace OPNsense\Abuseipdb;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm("general");
        $this->view->blacklistForm = $this->getForm("blacklist");
        $this->view->reporterForm = $this->getForm("reporter");
        $this->view->pick('OPNsense/Abuseipdb/index');
    }
}

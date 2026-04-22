{#
 # Copyright (c) 2026 Kai Voss / IT-Service NF
 # All rights reserved. BSD 2-Clause.
 #}

<script>
    $(document).ready(function() {
        var data_get_map = {'frm_general': "/api/abuseipdb/settings/get",
                            'frm_blacklist': "/api/abuseipdb/settings/get",
                            'frm_reporter': "/api/abuseipdb/settings/get"};

        mapDataToFormUI(data_get_map).done(function(sections){
            updateServiceControlUI('abuseipdb');
        });

        // Save all three tabs sequentially — saveFormToEndpoint handles one form at a time.
        function saveAll() {
            saveFormToEndpoint(
                url = "/api/abuseipdb/settings/set",
                formid = 'frm_general',
                callback_ok = function(){
                    saveFormToEndpoint(
                        url = "/api/abuseipdb/settings/set",
                        formid = 'frm_blacklist',
                        callback_ok = function(){
                            saveFormToEndpoint(
                                url = "/api/abuseipdb/settings/set",
                                formid = 'frm_reporter',
                                callback_ok = function(){
                                    $("#responseMsg").removeClass("hidden").html(
                                        "{{ lang._('Configuration saved.') }}"
                                    );
                                }
                            );
                        }
                    );
                }
            );
        }
        $("#saveAct").click(saveAll);

        $("#testConnectionAct").click(function(){
            ajaxCall(
                url = "/api/abuseipdb/service/test_connection",
                sendData = {},
                callback = function(data, status){
                    $("#responseMsg").removeClass("hidden").html(
                        "{{ lang._('Test result:') }} " + (data.output || data.message)
                    );
                }
            );
        });

        $("#downloadNowAct").click(function(){
            ajaxCall(
                url = "/api/abuseipdb/service/download",
                sendData = {},
                callback = function(data, status){
                    $("#responseMsg").removeClass("hidden").html(
                        "{{ lang._('Download:') }} " + (data.output || data.message)
                    );
                }
            );
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#blacklist">{{ lang._('Blacklist') }}</a></li>
    <li><a data-toggle="tab" href="#reporter">{{ lang._('Reporter') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="general" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
    <div id="blacklist" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': blacklistForm, 'id': 'frm_blacklist']) }}
    </div>
    <div id="reporter" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': reporterForm, 'id': 'frm_reporter']) }}
    </div>
</div>

<section class="page-content-main">
    <div class="content-box" style="padding: 15px;">
        <button class="btn btn-primary" id="saveAct">
            <b>{{ lang._('Save') }}</b>
        </button>
        <button class="btn btn-default" id="testConnectionAct">
            {{ lang._('Test connection') }}
        </button>
        <button class="btn btn-default" id="downloadNowAct">
            {{ lang._('Download blacklist now') }}
        </button>
        <br/><br/>
        <div id="responseMsg" class="alert alert-info hidden" role="alert"></div>
    </div>
</section>

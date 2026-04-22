PLUGIN_NAME=		abuseipdb
PLUGIN_VERSION=		0.1
PLUGIN_COMMENT=		AbuseIPDB integration (blacklist + reporter)
PLUGIN_MAINTAINER=	info@it-service-nf.de
PLUGIN_WWW=		https://github.com/KaiOppi/os-abuseipdb
PLUGIN_REVISION=	1

PLUGIN_DEPENDS=		py311-requests

.include "../../Mk/plugins.mk"

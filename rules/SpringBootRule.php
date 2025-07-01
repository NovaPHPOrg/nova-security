<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class SpringBootRule extends iRuleItem
{
    function name(): string
    {
        return "Spring Boot";
    }

    function description(): string
    {
        return "Spring Boot敏感路径检测。";
    }

    public function locations(): array
    {
        return [
            RuleLocation::PATHS
        ];
    }

    function regex(): array
    {
        return [
        new RuleRegex("Actuator Path Access", "/actuator(/auditLog|/auditevents|/autoconfig|/beans|/caches|/conditions|/configurationMetadata|/configprops|/dump|/env|/events|/exportRegisteredServices|/features|/flyway|/health|/heapdump|/healthcheck|/httptrace|/hystrix.stream|/info|/integrationgraph|/jolokia|/logfile|/loggers|/loggingConfig|/liquibase|/metrics|/mappings|/scheduledtasks|/swagger-ui.html|/prometheus|/refresh|/registeredServices|/releaseAttributes|/resolveAttributes|/sessions|/springWebflow|/shutdown|/sso|/ssoSessions|/statistics|/status|/threaddump|/trace)?", 2),
        new RuleRegex("API Documentation Access", "api(/index\\.html|/swagger-ui\\.html|/v2/api-docs)?", 2),
        new RuleRegex("Druid Path Access", "druid(/index\\.html|/login\\.html|/websession\\.html)?", 2),
        new RuleRegex("Heapdump Path Access", "/heapdump(\\.json)?", 3),
        new RuleRegex("SW Swagger UI Path Access", "swagger-ui", 2),
        new RuleRegex("Swagger Path Access", "swagger(/codes|/index.html|/static/index\\.html|/swagger-ui\\.html)?", 2)
    ];
    }
}

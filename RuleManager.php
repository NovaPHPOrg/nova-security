<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

use app\nova\plugin\security\rules\{BackupFileRule,BotRule,CommandInjectionRule,DnslogRule,LdapInjectionRule,PathOverflowRule,SensitiveFileExposureRule,SpringBootRule,SqlInjectionRule,SsrfRule,XssRule,XxeRule};
use nova\framework\http\Request;

class RuleManager
{
    /**
     * @var class-string<iRuleItem>[]
     */
    private readonly array $rules;

    public function __construct(
        private readonly Request $request,
        array $rules = [
            BackupFileRule::class,
            BotRule::class,
            CommandInjectionRule::class,
            DnslogRule::class,
            LdapInjectionRule::class,
            PathOverflowRule::class,
            SensitiveFileExposureRule::class,
            SpringBootRule::class,
            SqlInjectionRule::class,
            SsrfRule::class,
            XssRule::class,
            XxeRule::class,
        ]
    ) {
        $this->rules = $rules;
    }

    public function check(): int
    {
        foreach ($this->rules as $ruleClass) {
            /** @var iRuleItem $rule */
            $rule = new $ruleClass();

            foreach ($rule->locations() as $location) {
                foreach ($this->payloadsForLocation($location) as $payload) {
                    $count = $rule->match($payload);
                    if ($count > 0) {
                        return $count;
                    }
                }
            }
        }

        return 0;
    }

    /**
     * Return iterable strings for given rule location.
     *
     * @return iterable<string>
     */
    private function payloadsForLocation(RuleLocation $location): iterable
    {
        return match ($location) {
            RuleLocation::PATHS      => [$this->request->getUri()],
            RuleLocation::HEADERS    => array_values($this->request->getHeaders()),
            RuleLocation::PARAMETERS => array_filter($this->request->arg(), 'is_string'),
            RuleLocation::BODY       => $this->request->isPost() ? [$this->request->raw()] : [],
            default                  => [],
        };
    }
}

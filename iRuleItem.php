<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

use nova\framework\core\Logger;

abstract class iRuleItem
{
   abstract function name(): string;

  abstract  function description(): string;

 abstract   function regex():array;


    function locations():array{
        return [
          RuleLocation::HEADERS,
          RuleLocation::PATHS,
          RuleLocation::PARAMETERS,
          RuleLocation::BODY,
        ];
    }

    function match(string $data):int{
        /**
         * @var $regex RuleRegex
         */
        foreach ($this->regex() as  $regex){
            if(preg_match("/{$regex->regex}i",$data)){
                Logger::debug("waf matched $data to {$regex->regex}");
                  return $regex->confidence;
            }
        }
        return 0;
    }

}
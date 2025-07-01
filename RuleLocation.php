<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

enum RuleLocation:string{
    case HEADERS = 'headers';//头部
    case PATHS = 'paths';//请求路径
    case PARAMETERS = 'parameters';//包括post\get\session
    case BODY = 'body';
}
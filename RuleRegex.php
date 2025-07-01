<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

class RuleRegex
{
    public string $name;
    public int $confidence = 1;

    public string $regex;

    public function __construct(string $name,string $regex,int $confidence)
    {
        $this->name = $name;
        $this->regex = $regex;
        $this->confidence = $confidence;
    }
}
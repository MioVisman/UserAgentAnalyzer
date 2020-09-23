# UserAgentAnalyzer

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

The browser/OS or robot detection by user agent.

## Requirements

* PHP 5.6.0+

## Installation

composer require miovisman/useragentanalyzer

## Example

``` php
$uaa = new UserAgentAnalyzer\UserAgentAnalyzer();

$ua = 'Mozilla/5.0 (Linux; Android 6.0.1; SM-T550 Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/51.0.2704.81 Safari/537.36 GSA/6.1.28.21.arm';
$result = $uaa->analyse($ua);
var_dump($result);

#array(8) {
#  ["isMobile"]=>       bool(true)
#  ["isRobot"]=>        bool(false)
#  ["botName"]=>        NULL
#  ["botVersion"]=>     NULL
#  ["browserName"]=>    string(15) "Android WebView"
#  ["browserVersion"]=> string(3) "4.0"
#  ["osName"]=>         string(7) "Android"
#  ["osVersion"]=>      string(5) "6.0.1"
#}

$ua = 'Mozilla/5.0 (compatible; DuckDuckGo-Favicons-Bot/1.0; +http://duckduckgo.com)';
$result = $uaa->analyse($ua);
var_dump($result);

#array(8) {
#  ["isMobile"]=>       NULL
#  ["isRobot"]=>        bool(true)
#  ["botName"]=>        string(23) "DuckDuckGo-Favicons-Bot"
#  ["botVersion"]=>     string(3) "1.0"
#  ["browserName"]=>    NULL
#  ["browserVersion"]=> NULL
#  ["osName"]=>         NULL
#  ["osVersion"]=>      NULL
#}
```

## License

This project is under MIT license. Please see the [license file](LICENSE) for details.

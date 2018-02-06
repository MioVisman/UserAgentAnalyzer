<?php

/**
 * @copyright  Copyright (c) 2018 Visman. All rights reserved.
 * @author     Visman <mio.visman@yandex.ru>
 * @link       https://github.com/MioVisman/UserAgentAnalyzer
 * @license    https://opensource.org/licenses/MIT The MIT License (MIT)
 */

namespace UserAgentAnalyzer;

use InvalidArgumentException;

class UserAgentAnalyzer
{
    protected $ua;
    protected $details;
    protected $result;

    protected $pattern = '%\b
        (
            [a-z]
            (?:
                [a-z]+(?:-[a-z]+)*(?:\ [a-z]{1,2}(?![\w.]))*
            |
                [a-z\d]+
            )
        )
        (\d+(?=[/;\ ]))?
        [^a-z\d;]*
        (?:
            (
                \d+(?:[._][\dx]+)*
            )
            [^\s;/(),]*
        )?%ix';

    protected $clean = [
        '%\((?:KHTML|Linux|Mac|Windows|X11)[^)]*\)?%i',
        '%\b(?:Apple|Chrom|compatible|Firefox|Gecko|(?<!\-)Mobile(?=[/ ])|Opera|OPR|Presto|Safari|Version)[^\s]*%i',
        '%\b(?:InfoP|Intel|Linux|Mac|MRA|MRS|MSIE|SV|Trident|Win|WOW|X\d)[^;)]*[;)]?%i',
        '%\bMozi[^\s]*[ ()]*%i',
        '%\b[a-z]{1,2}[;)]%i',
        '%\.NET[^;)]*[;)]?%i',
        '%\b(?:;|v[.\d]).*%i',
        '%(?:[/()]|\d\.[x\d]).*%',
        '%[^a-z\d\.!_-]+%i',
        '%(?<![a-z])-|-(?![a-z])%i',
        '%\s{2,}%',
    ];

    protected $os = [ //        name            mobile method
        'Windows NT'       => ['Windows NT',    false, 'windowsnt'],
        'Windows CE'       => ['Windows CE',    true,  null],
        'Windows'          => ['Windows',       false, 'windows'],
        'iPad'             => ['iOS',           true,  'ios'],
        'iPod'             => ['iOS',           true,  'ios'],
        'iPhone'           => ['iOS',           true,  'ios'],
        'Mac OS X'         => ['Mac OS X',      false, 'macosx'],
        'Tizen'            => ['Tizen',         true,  null],
        'Android'          => ['Android',       true,  null],
        'Adr'              => ['Android',       true,  null],
        'CrOS'             => ['Chrome OS',     false, null],
        'FreeBSD'          => ['FreeBSD',       false, null],
        'NetBSD'           => ['NetBSD',        false, null],
        'OpenBSD'          => ['OpenBSD',       false, null],
        'CentOS'           => ['CentOS',        false, null],
        'SUSE'             => ['openSUSE',      false, null],
        'Fedora'           => ['Fedora',        false, null],
        'Mint'             => ['Linux Mint',    false, null],
        'Ubuntu'           => ['Ubuntu',        false, null],
        'Red Hat'          => ['Red Hat',       false, null],
        'Debian'           => ['Debian',        false, null],
        'Linux'            => ['Linux',         false, null],
        'X11'              => ['Unix',          false, null],
        'Macintosh'        => ['Macintosh',     false, null],
        'Bada'             => ['Bada',          true,  null],
        'BB'               => ['BlackBerry OS', true,  null],
        'BlackBerry'       => ['BlackBerry OS', true,  'bb'],
        'SymbianOS'        => ['Symbian OS',    true,  null],
        'SymbOS'           => ['Symbian OS',    true,  null],
        'Series'           => ['Symbian OS',    true,  'series'],
        'MIDP'             => ['Java',          true,  'java'],
    ];

    protected $browser = [ //   name                      mobile method
        'Browser'          => [null,                       null, 'browser'],
        'UCBrowser'        => ['UC Browser',               null, null],
        'UCWEB'            => ['UC Browser',               null, null],
        'TriCore'          => ['Avant Browser',            null, null],
        'Opera'            => ['Opera',                    null, 'opera'],
        'Maxthon'          => ['Maxthon',                  null, null],
        'MxBrowser'        => ['Maxthon',                  null, null],
        'Sleipnir'         => ['Sleipnir',                 null, null],
        'Lunascape'        => ['Lunascape',                null, null],
        'IEMobile'         => ['Internet Explorer Mobile', true, null],
        'Edge'             => ['Microsoft Edge',           null, null],
        'MSIE'             => ['Internet Explorer',        null, null],
        'OPR'              => ['Opera',                    null, null],
        'Chromium'         => ['Chromium',                 null, null],
        'CriOS'            => ['Chrome',                   null, null],
        'Vivaldi'          => ['Vivaldi',                  null, null],
        'YaBrowser'        => ['Yandex Browser',           null, null],
        'QupZilla'         => ['QupZilla',                 null, null],
        'Chrome'           => ['Chrome',                   null, 'crome'],
        'Arora'            => ['Arora',                    null, null],
        'Epiphany'         => ['Epiphany',                 null, null],
        'Galeon'           => ['Galeon',                   null, null],
        'Konqueror'        => ['Konqueror',                null, null],
        'Otter'            => ['Otter Browser',            null, 'otter'],
        'Dooble'           => ['Dooble',                   null, null],
        'NokiaBrowser'     => ['Nokia Browser',            null, null],
        'Safari'           => ['Safari',                   null, 'safari'],
        'Flock'            => ['Flock',                    null, null],
        'Iceweasel'        => ['Iceweasel',                null, null],
        'SeaMonkey'        => ['SeaMonkey',                null, null],
        'K-Meleon'         => ['K-Meleon',                 null, null],
        'Camino'           => ['Camino',                   null, null],
        'Firefox'          => ['Firefox',                  null, null],
        'Trident'          => ['Internet Explorer',        null, 'trident'],
        'Dolfin'           => ['Dolfin',                   null, null],
        'Lynx'             => ['Lynx',                     null, null],
        'Links'            => ['Links',                    null, null],
        'ELinks'           => ['ELinks',                   null, null],
        'NetSurf'          => ['NetSurf',                  null, null],
        'BrowserNG'        => ['Nokia Browser',            null, null],
    ];

    protected $windows = [
        '5.0'  => 'Windows 2000',
        '5.1'  => 'Windows XP',
        '5.2'  => 'Windows XP',
        '6.0'  => 'Windows Vista',
        '6.1'  => 'Windows 7',
        '6.2'  => 'Windows 8',
        '6.3'  => 'Windows 8.1',
        '6.4'  => 'Windows 10',
        '10.0' => 'Windows 10',
    ];

    public function analyse($ua = null)
    {
        $this->details = [];

        if (null === $ua) {
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $ua = $_SERVER['HTTP_USER_AGENT'];
            } else {
                throw new InvalidArgumentException('User agent is missing');
            }
        }

        $this->ua     = $ua;
        $this->result = [
            'isMobile'       => null,
            'isRobot'        => null,
            'botName'        => null,
            'botVersion'     => null,
            'browserName'    => null,
            'browserVersion' => null,
            'osName'         => null,
            'osVersion'      => null,
        ];

        $count   = 0;
        $uaLC    = strtolower($ua);
        $uaIn    = $ua;
        $bot     = strpos($uaLC, 'bot');
        $spider  = strpos($uaLC, 'spider');
        $crawler = strpos($uaLC, 'crawler');
        $mozilla = strpos($uaLC, 'mozilla');

        if ((false !== $bot && false === strpos($ua, 'CUBOT'))
            || (false !== $spider && false === strpos($ua, 'GLX Spider'))
            || false !== $crawler
        ) {
            $count += 1;
        }

        if (false !== strpos($uaLC, 'http')) {
            $count += 0.5;
            $uaIn   = preg_replace('%https?:[^);]*[);]?%i', ' ', $uaIn);
        }

        if (false !== strpos($uaIn, 'www.')) {
            $count += 0.5;
            $uaIn   = preg_replace('%www\.[^)]*[);]?%i', ' ', $uaIn);
        }

        if (false !== strpos($uaIn, '@')) {
            $count += 0.5;
            $uaIn   = preg_replace('%[^\s/;()]+@[^);]*[);]?%i', ' ', $uaIn);
        }

        if (false !== $mozilla
            && false === strpos($ua, 'Gecko')
            && (false === strpos($ua, '(compatible; MSIE ') || false === strpos($ua, 'Windows'))
        ) {
            $count += 0.3;
        }

        if ($count < 1) {
            $this->details($uaIn);

            foreach (['os', 'browser'] as $type) {
                foreach ($this->$type as $key => $data) {
                    if (! isset($this->details[$key])) {
                        continue;
                    }

                    $data['v'] = $this->details[$key];

                    if (isset($data[2])) {
                        $data = $this->{$data[2]}($data, $key);
                        if (false === $data) {
                            continue;
                        }
                    }

                    $this->result[$type . 'Name'] = $data[0];
                    if (null !== $data[1]) {
                        $this->result['isMobile'] = $data[1];
                    }

                    if ('' != $data['v']) {
                        $this->result[$type . 'Version'] = $data['v'];
                    }

                    break;
                }

                if (null === $this->result[$type . 'Name']) {
                    $count += 0.5;
                    if ($count >= 1) {
                        break;
                    }
                }
            }
        }

        if ($count < 1) {
            $this->result['isRobot'] = false;
#            $this->result['details'] = $this->details;

            return $this->result;
        }

        $this->result['isRobot'] = true;

        if (false !== $bot && preg_match('%[^;()]*bot[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $spider && preg_match('%[^;()]*spider[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $crawler && preg_match('%[^;()]*crawler[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $mozilla) {
            $uaIn = preg_replace('%Mozilla.*?compatible[; ]*%i', ' ', $uaIn);
        } elseif (false !== strpos($uaLC, 'docomo')) {
            $uaIn = preg_replace('%DoCoMo.*?compatible[; ]*%i', ' ', $uaIn);
        }

        $uaIn = trim(preg_replace($this->clean, ' ', $uaIn), ' ._-');
        $len  = strlen($uaIn);

        if ($len < 3 || $len > 30 || count(preg_split('%[ ._-]%', $uaIn)) > 4) {
            $uaIn = null;
        } elseif (preg_match('%' . preg_quote($uaIn, '%'). '[v /.-]*(\d+(\.[x\d]+)*)%i', $ua, $match)) {
            $this->result['botVersion'] = $match[1];
        }

        $this->result['botName'] = $uaIn;
#        $this->result['details'] = $this->details;

        return $this->result;
    }

    protected function details($ua)
    {
        preg_match_all($this->pattern, $ua, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            if (! isset($m[3])) {
                $m[3] = '';
            }
            if (empty($this->details[$m[1]])) {
                if (isset($m[2]) && '' !== $m[2]) {
                    $this->details[$m[1]] = $m[2];
                    if (empty($this->details[$m[1] . $m[2]])) {
                        $this->details[$m[1] . $m[2]] = $m[3];
                    }
                } else {
                    $this->details[$m[1]] = $m[3];
                }
            }
        }
    }

    /**
     * Windows Phone, Windows Mobile, Windows
     */
    protected function windows(array $data, $name)
    {
        if (isset($this->details['Phone OS'])) {
            $data[0]   = 'Windows Phone';
            $data[1]   = true;
            $data['v'] = $this->details['Phone OS'];
        } elseif (isset($this->details['Phone'])) {
            $data[0]   = 'Windows Phone';
            $data[1]   = true;
            $data['v'] = $this->details['Phone'];
        } elseif (false !== strpos($this->ua, 'Windows Mobile')) {
            $data[0]   = 'Windows Mobile';
            $data[1]   = true;
        }
        return $data;
    }

    /**
     * Windows NT
     */
    protected function windowsnt(array $data, $name)
    {
        if (isset($this->windows[$data['v']])) {
            $data[0] = $this->windows[$data['v']];
        }
        return $data;
    }

    /**
     * iOS
     */
    protected function ios(array $data, $name)
    {
        if (! empty($this->details['iPhone OS'])) {
            $data['v'] = str_replace('_', '.', $this->details['iPhone OS']);
        } elseif (! empty($this->details['CPU OS'])) {
            $data['v'] = str_replace('_', '.', $this->details['CPU OS']);
        }
        return $data;
    }

    /**
     * Mac OS X
     */
    protected function macosx(array $data, $name)
    {
        $data['v'] = str_replace('_', '.', $data['v']);
        return $data;
    }

    /**
     * BlackBerry OS
     */
    protected function bb(array $data, $name)
    {
        if (! empty($this->details[$name . $data['v']])) {
            $data['v'] = $this->details[$name . $data['v']];
        } elseif ($data['v'] > 999) {
            $data['v'] = null;
        }
        return $data;
    }

    /**
     * Symbian OS
     */
    protected function series(array $data, $name)
    {
        if (in_array($data['v'], ['40', '60', '80'])) {
            $data['v'] = null;
            return $data;
        }  else {
            return false;
        }
    }

    /**
     * Java
     */
    protected function java(array $data, $name)
    {
        $data['v'] = null;
        return $data;
    }

    /**
     * UC Browser, Avant Browser
     */
    protected function browser(array $data, $name)
    {
        if (isset($this->details['UC'])) {
            $data[0] = 'UC Browser';
        } elseif (isset($this->details['Avant'])) {
            $data[0] = 'Avant Browser';
        } else {
            return false;
        }
        return $data;
    }

    /**
     * Opera, Opera Mini, Opera Mobi
     */
    protected function opera(array $data, $name)
    {
        if (isset($this->details['Mobi'])) {
            $data[0]   = 'Opera Mobile';
            $data['v'] = $this->details['Mobi'];
        } elseif (isset($this->details['Mini'])) {
            $data[0]   = 'Opera Mini';
            $data['v'] = $this->details['Mini'];
        } elseif ('9.80' == $data['v'] && ! empty($this->details['Version'])) {
            $data['v'] = $this->details['Version'];
        }
        return $data;
    }

    /**
     * Chrome, Android WebView
     */
    protected function crome(array $data, $name)
    {
        if ('Android' === $this->result['osName']) {
            if (! empty($this->details['Version'])) {
                $data[0]   = 'Android WebView';
                $data['v'] = $this->details['Version'];
            } elseif (isset($this->details['wv'])) {
                $data[0]   = 'Android WebView';
                $data['v'] = null;
            }
        }
        return $data;
    }

    /**
     * Otter Browser
     */
    protected function otter(array $data, $name)
    {
        if (empty($data['v'])) {
            return false;
        } else {
            return $data;
        }
    }

    /**
     * Safari, Android Browser(?), BlackBerry Browser
     */
    protected function safari(array $data, $name)
    {
        if (! empty($this->details['Version'])) {
            $data['v'] = $this->details['Version'];
        }
        if ('Android' === $this->result['osName']) {
            $data[0] = 'Android Browser';
        } elseif ('BlackBerry OS' === $this->result['osName']) {
            $data[0] = 'BlackBerry Browser';
        }
        return $data;
    }

    /**
     * IE
     */
    protected function trident(array $data, $name)
    {
        switch ($data['v']) {
            case '7.0':
                $data['v'] = '11';
                break;
            case '6.0':
                $data['v'] = '10';
                break;
            case '5.0':
                $data['v'] = '9';
                break;
            case '4.0':
                $data['v'] = '8';
                break;
            default:
                return false;
        }
        return $data;
    }
}
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
    const VERSION = '1.0027';

    protected $ua;
    protected $details;
    protected $result;

    protected $pattern = '%(/)?\b
        (?=[a-z\d])
        (?:
            (?:v\.?)?
            ( \d+(?:[._][\w.-]+)? )
        |
            ( [a-z._-]{2,} )
            ( \d+(?:\.[\w.-]+)? )
        |
            ( [\w.-]+(?:\ [a-z]{1,2})* )
        )
        (?![\w.-])%ix';

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

    protected $os = [ //        name            mobile ver      no
        'Windows NT'       => ['Windows',       false, true, 0, null],
        'Windows CE'       => ['Windows CE',    true,  null, 2, null],
        'Windows'          => ['Windows',       false, null, 0, 'Windows NT'],
        'iPad'             => ['iOS',           true,  null, 3, null],
        'iPod'             => ['iOS',           true,  null, 3, null],
        'iPhone'           => ['iOS',           true,  null, 3, null],
        'Mac OS X'         => ['Mac OS X',      false, null, 2, null],
        'Tizen'            => ['Tizen',         true,  null, 3, null],
        'webOS'            => ['webOS',         true,  true, 2, null],
        'hpwOS'            => ['webOS',         true,  true, 2, null],
        'Android'          => ['Android',       true,  null, 2, null],
        'Adr'              => ['Android',       true,  null, 2, null],
        'RemixOS'          => ['Remix OS',      false, null, 2, null],
        'CrOS'             => ['Chrome OS',     false, null, 2, null],
        'CentOS'           => ['CentOS',        false, null, 2, null],
        'SUSE'             => ['openSUSE',      false, null, 2, null],
        'Fedora'           => ['Fedora',        false, null, 1, null],
        'Mint'             => ['Linux Mint',    false, null, 2, null],
        'Kubuntu'          => ['Kubuntu',       false, null, 2, null],
        'Ubuntu'           => ['Ubuntu',        false, null, 2, null],
        'Hat'              => ['Red Hat',       false, null, 2, null],
        'Debian'           => ['Debian',        false, null, 2, null],
        'Slackware'        => ['Slackware',     false, null, 2, null],
        'MeeGo'            => ['MeeGo',         null,  null, 2, null],
        'Linux'            => ['Linux',         false, null, 2, null],
        'FreeBSD'          => ['FreeBSD',       false, null, 2, null],
        'NetBSD'           => ['NetBSD',        false, null, 2, null],
        'OpenBSD'          => ['OpenBSD',       false, null, 2, null],
        'X11'              => ['Unix',          false, null, 0, null],
        'Macintosh'        => ['Macintosh',     false, null, 3, null],
        'Bada'             => ['Bada',          true,  null, 2, null],
        'BB'               => ['BlackBerry OS', true,  true, 1, null],
        'BlackBerry'       => ['BlackBerry OS', true,  null, 2, null],
        'SymbianOS'        => ['Symbian OS',    true,  null, 2, null],
        'SymbOS'           => ['Symbian OS',    true,  null, 2, null],
        'Series'           => ['Symbian OS',    true,  null, 0, null],
        'Profile'          => ['Java',          true,  true, 0, null],
        'J2ME'             => ['Java',          true,  true, 0, null],
        'KAIOS'            => ['KaiOS',         true,  true, 2, null],
        'KaiOS'            => ['KaiOS',         true,  true, 2, null],
        'Gecko'            => ['Firefox OS',    true,  true, 0, 'AppleWebKit'],
    ];

    protected $browser = [ //   name                      mobile ver      no
        'Browser'          => [null,                       null, null, 2, null],
        'UCBrowser'        => ['UC Browser',               null, null, 2, null],
        'UCWEB'            => ['UC Browser',               null, null, 2, null],
        'TriCore'          => ['Avant Browser',            null, null, 2, null],
        'Opera'            => ['Opera',                    null, null, 2, null],
        'Maxthon'          => ['Maxthon',                  null, null, 2, null],
        'MxBrowser'        => ['Maxthon',                  null, null, 2, null],
        'Sleipnir'         => ['Sleipnir',                 null, null, 2, null],
        'Lunascape'        => ['Lunascape',                null, null, 2, null],
        'IEMobile'         => ['Internet Explorer Mobile', true, true, 2, null],
        'Edge'             => ['Microsoft Edge',           null, true, 2, null],
        'MSIE'             => ['Internet Explorer',        null, true, 2, null],
        'OPR'              => ['Opera',                    null, true, 2, null],
        'OPiOS'            => ['Opera for iOS',            null, true, 2, null],
        'Epiphany'         => ['Epiphany',                 null, true, 2, null],
        'Chromium'         => ['Chromium',                 null, true, 2, null],
        'CriOS'            => ['Chrome for iOS',           null, null, 2, null],
        'Vivaldi'          => ['Vivaldi',                  null, true, 2, null],
        'YaBrowser'        => ['Yandex Browser',           null, true, 2, null],
        'QupZilla'         => ['QupZilla',                 null, true, 2, null],
        'Iron'             => ['SRWare Iron',              null, null, 2, null],
        'SamsungBrowser'   => ['Samsung Internet',         null, true, 2, null],
        'Puffin'           => ['Puffin',                   true, true, 2, null],
        'Konqueror'        => ['Konqueror',                null, null, 2, null],
        'konqueror'        => ['Konqueror',                null, null, 2, null],
        'Chrome'           => ['Chrome',                   null, true, 2, null],
        'FxiOS'            => ['Firefox for iOS',          null, null, 2, null],
        'Arora'            => ['Arora',                    null, null, 2, null],
        'Galeon'           => ['Galeon',                   null, null, 2, null],
        'Otter'            => ['Otter Browser',            null, true, 2, null],
        'Dooble'           => ['Dooble',                   null, null, 2, null],
        'NokiaBrowser'     => ['Nokia Browser',            true, null, 2, null],
        'BrowserNG'        => ['Nokia Browser',            true, null, 2, null],
        'Flock'            => ['Flock',                    null, null, 2, null],
        'Iceweasel'        => ['Iceweasel',                null, null, 2, null],
        'SeaMonkey'        => ['SeaMonkey',                null, null, 2, null],
        'K-Meleon'         => ['K-Meleon',                 null, null, 2, null],
        'Camino'           => ['Camino',                   null, true, 2, null],
        'PaleMoon'         => ['Pale Moon',                null, null, 2, null],
        'Firefox'          => ['Firefox',                  null, true, 2, 'AppleWebKit'],
        'Trident'          => ['Internet Explorer',        null, true, 2, null],
        'Dolfin'           => ['Dolfin',                   null, null, 2, null],
        'wOSBrowser'       => ['webOS Browser',            null, true, 2, null],
        'AppleWebKit'      => ['WebKit',                   null, true, 2, 'Gecko'],
        'Lynx'             => ['Lynx',                     null, null, 2, null],
        'Links'            => ['Links',                    null, null, 2, null],
        'ELinks'           => ['ELinks',                   null, null, 2, null],
        'NetSurf'          => ['NetSurf',                  null, null, 2, null],
        'NetFront'         => ['NetFront',                 true, true, 2, null],
    ];

    protected $windowsnt = [
        '4.0'  => 'NT 4.0',
        '5.0'  => '2000',
        '5.01' => '2000',
        '5.1'  => 'XP',
        '5.2'  => 'XP',
        '6.0'  => 'Vista',
        '6.1'  => '7',
        '6.2'  => '8',
        '6.3'  => '8.1',
        '6.4'  => '10',
        '10.0' => '10',
    ];

    protected $firefoxos = [
        '18.0' => '1.0.1',
        '18.1' => '1.1',
        '26.0' => '1.2',
        '28.0' => '1.3',
        '30.0' => '1.4',
        '32.0' => '2.0',
        '34.0' => '2.1',
        '37.0' => '2.2',
        '44.0' => '2.5',
    ];

    protected $trident = [
        '4.0' => '8.0',
        '5.0' => '9.0',
        '6.0' => '10.0',
        '7.0' => '11.0',
    ];

    protected $puffin = [
        'IP' => ['iOS',           true],
        'IT' => ['iOS',           true],
        'AP' => ['Android',       true],
        'AT' => ['Android',       true],
        'WP' => ['Windows Phone', true],
        'WD' => ['Windows',       false],
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

        $prob    = 0;
        $uaLC    = \strtolower($ua);
        $uaIn    = $ua;
        $bot     = \strpos($uaLC, 'bot');
        $spider  = \strpos($uaLC, 'spider');
        $crawler = \strpos($uaLC, 'crawler');
        $preview = \strpos($uaLC, 'preview');
        $mozilla = \strpos($uaLC, 'mozilla');

        if ((false !== $bot && false === \strpos($ua, 'CUBOT'))
            || (false !== $spider && false === \strpos($ua, 'GLX Spider'))
            || false !== $crawler
            || false !== $preview
        ) {
            $prob += 1;
        }
        if (false !== \strpos($uaLC, 'search')) {
            $prob += 0.4;
        }
        if (false !== \strpos($uaLC, 'http')) {
            $uaIn  = \preg_replace('%https?:[^);]*[);]?%i', ' ', $uaIn, -1, $count);
            $prob += 0.4 * $count;
        }
        if (false !== \strpos($uaIn, 'www.')) {
            $uaIn  = \preg_replace('%www\.[^)]*[);]?%i', ' ', $uaIn, -1, $count);
            $prob += 0.4 * $count;
        }
        if (false !== \strpos($uaIn, '@')) {
            $uaIn  = \preg_replace('%[^\s/;()]+@[^);]*[);]?%i', ' ', $uaIn, -1, $count);
            $prob += 0.4 * $count;
        }
        if (false !== $mozilla
            && false === \strpos($ua, 'Gecko')
            && (false === \strpos($ua, '(compatible; MSIE ') || false === \strpos($ua, 'Windows'))
        ) {
            $prob += 0.3;
        }
        if (false !== \strpos($uaLC, 'like')) {
            $uaIn = \preg_replace('%\blike[^()]*(?:\([^)]*\)[^()]*)*%i', '', $uaIn);
        }

        if ($prob < 1) {
            $this->details($uaIn);

            foreach (['os', 'browser'] as $type) {
                foreach ($this->$type as $key => $data) {
                    if (! isset($this->details[$key])
                        || (true === $data[2] && '' == $this->details[$key])
                    ) {
                        continue;
                    }
                    if (null !== $data[3]) {
                        $args = \explode(',', $data[4]);
                        if (null !== $this->getValue(...$args)) {
                            continue;
                        }
                    }

                    $data['v'] = $this->details[$key];
                    $method    = \str_replace(' ', '', $key);

                    if (\method_exists($this, $method)) {
                        $data = $this->{$method}($data, $key);
                        if (false === $data) {
                            continue;
                        }
                    }

                    $this->result[$type . 'Name'] = $data[0];
                    if (null !== $data[1]) {
                        $this->result['isMobile'] = $data[1];
                    }
                    if (! empty($data['v'])) {
                        if ($data[3]) {
                            if (\preg_match('%^(\d+)(?:[._]([\dx]+)(?:[._]([\dx]+))?)?%i', $data['v'], $match)) {
                                $this->result[$type . 'Version'] = \implode('.', \array_slice($match, 1, $data[3]));
                            }
                        } else {
                            $this->result[$type . 'Version'] = $data['v'];
                        }
                    }

                    break;
                }

                if (null === $this->result[$type . 'Name']) {
                    $prob += 0.5;
                    if ($prob >= 1) {
                        break;
                    }
                }
            }
        }

        if ($prob < 1) {
            $this->result['isRobot'] = false;
#            $this->result['details'] = $this->details;
            if (true !== $this->result['isMobile']) {
                if (null !== $this->getValue('Mobile', 'Tablet')) {
                    $this->result['isMobile'] = true;
                }
            } elseif (null !== $this->getValue('SMART-TV', 'TV')) {
                $this->result['isMobile'] = false;
            }

            return $this->result;
        }

        $this->result['isRobot'] = true;

        if (false !== $bot && \preg_match('%[^;()]*bot[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $spider && \preg_match('%[^;()]*spider[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $crawler && \preg_match('%[^;()]*crawler[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $preview && \preg_match('%[^;()]*preview[a-z\d\.!_-]*%i', $uaIn, $match)) {
            $uaIn = $match[0];
        } elseif (false !== $mozilla) {
            $uaIn = \preg_replace('%Mozilla.*?compatible[; ]*%i', ' ', $uaIn);
        } elseif (false !== \strpos($uaLC, 'docomo')) {
            $uaIn = \preg_replace('%DoCoMo.*?compatible[; ]*%i', ' ', $uaIn);
        }

        $uaIn = \trim(\preg_replace($this->clean, ' ', $uaIn), ' ._-');
        $len  = \strlen($uaIn);

        if ($len < 3 || $len > 30 || \count(\preg_split('%[ ._-]%', $uaIn)) > 4) {
            $uaIn = null;
        } elseif (\preg_match('%' . \preg_quote($uaIn, '%'). '[v /.-]*(\d+(\.[x\d]+)*)%i', $ua, $match)) {
            $this->result['botVersion'] = $match[1];
        }

        $this->result['botName'] = $uaIn;
#        $this->result['details'] = $this->details;

        return $this->result;
    }

    protected function details($ua)
    {
        \preg_match_all($this->pattern, $ua, $matches, \PREG_SET_ORDER);

        $cur = null;
        foreach ($matches as $m) {
            if (! empty($m[1])) {
                if (isset($m[5])) {
                    $next  = $m[5];
                    $value = $m[5];
                } elseif (isset($m[3])) {
                    $next  = $m[3] . $m[4];
                    $value = $m[3] . $m[4];
                } else {
                    $next  = null;
                    $value = $m[2];
                }
            } elseif (isset($m[5])) {
                $cur   = null;
                $next  = $m[5];
                $value = '';
            } elseif (isset($m[3])) {
                $cur   = rtrim($m[3], '-_.');
                $next  = $m[3] . $m[4];
                $value = $m[4];
            } else {
                $next  = null;
                $value = $m[2];
            }

            if ($cur && empty($this->details[$cur])) {
                $this->details[$cur] = $value;
            }
            $cur = $next;
            if ($cur && ! isset($this->details[$cur])) {
                $this->details[$cur] = '';
            }
        }
    }

    protected function getValue(...$args)
    {
        if (true === \end($args)) {
            $noEmpty = true;
            \array_pop($args);
        } else {
            $noEmpty = false;
        }

        foreach ($args as $name) {
            if (isset($this->details[$name])) {
                if ($noEmpty && '' == $this->details[$name]) {
                    continue;
                } else {
                    return $this->details[$name];
                }
            }
        }
        return null;
    }

    /**
     * Windows NT
     */
    protected function WindowsNT(array $data, $name)
    {
        if (isset($this->windowsnt[$data['v']])) {
            $data['v'] = $this->windowsnt[$data['v']];
            return $data;
        } else {
            return false;
        }
    }

    /**
     * Windows Phone, Windows Mobile, Windows
     */
    protected function Windows(array $data, $name)
    {
        if (null !== ($v = $this->getValue('Phone OS', 'Phone'))) {
            $data[0]   = 'Windows Phone';
            $data[1]   = true;
            $data['v'] = $v;
        } elseif (false !== \strpos($this->ua, 'Windows Mobile')) {
            $data[0]   = 'Windows Mobile';
            $data[1]   = true;
        } elseif (! \in_array($data['v'], ['95', '98'])) {
            $data['v'] = null;
        } elseif ('98' === $data['v'] && '4.90' === $this->getValue('9x')) {
            $data['v'] = 'ME';
        }
        return $data;
    }

    /**
     * iPad iOS
     */
    protected function iPad(array $data, $name)
    {
        $data['v'] = $this->getValue('iPhone OS', 'CPU OS', true);
        return $data;
    }

    /**
     * iPod iOS
     */
    protected function iPod(array $data, $name)
    {
        $data['v'] = $this->getValue('iPhone OS', 'CPU OS', true);
        return $data;
    }

    /**
     * iPhone iOS
     */
    protected function iPhone(array $data, $name)
    {
        $data['v'] = $this->getValue('iPhone OS', 'CPU OS', true);
        return $data;
    }

    /**
     * Mac OS X
     */
    protected function MacOSX(array $data, $name)
    {
        $data['v'] = $data['v'];
        return $data;
    }

    /**
     * Chrome OS
     */
    protected function CrOS(array $data, $name)
    {
        if (null !== ($v = $this->getValue('Chrome', true))) {
            $data['v'] = $v;
        }
        return $data;
    }

    /**
     * CentOS
     */
    protected function CentOS(array $data, $name)
    {
        if (\preg_match('%\.el(\d+)[^\s;/]*\.centos%', $data['v'], $match)) {
            $data['v'] = $match[1];
        } else {
            $data['v'] = null;
        }
        return $data;
    }

    /**
     * Fedora
     */
    protected function Fedora(array $data, $name)
    {
        if (\preg_match('%\.fc\K\d+%', $data['v'], $match)) {
            $data['v'] = $match[0];
        } else {
            $data['v'] = null;
        }
        return $data;
    }

    /**
     * Red Hat, Red Hat Enterprise Linux
     */
    protected function Hat(array $data, $name)
    {
        if (! isset($this->details['Red'])) {
            return false;
        }
        if (\preg_match('%\.el\K\d+%', $this->ua, $match)) {
            $data[0]  .= ' Enterprise Linux';
            $data['v'] = $match[0];
        }
        return $data;
    }

    /**
     * BlackBerry OS
     */
    protected function BlackBerry(array $data, $name)
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
    protected function Series(array $data, $name)
    {
        if (\in_array($data['v'], ['40', '60', '80'])) {
            $data['v'] = null;
            return $data;
        }  else {
            return false;
        }
    }

    /**
     * Java
     */
    protected function Profile(array $data, $name)
    {
        if ('MIDP' == \substr($data['v'], 0, 4)) {
            $data['v'] = null;
            return $data;
        } else {
            return false;
        }
    }

    /**
     * Java
     */
    protected function J2ME(array $data, $name)
    {
        return $this->Profile($data, $name);
    }

    /**
     * Firefox OS
     */
    protected function Gecko(array $data, $name)
    {
        if (! empty($this->details['rv'])
            && ! empty($this->details['Firefox'])
            && isset($this->firefoxos[$data['v']])
        ) {
            $data['v'] = $this->firefoxos[$data['v']];
            return $data;
        } else {
            return false;
        }
    }

    /**
     * UC Browser, Avant Browser
     */
    protected function Browser(array $data, $name)
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
    protected function Opera(array $data, $name)
    {
        $v = empty($this->details['Version']) ? null : $this->details['Version'];

        if (isset($this->details['Mobi'])) {
            $data[0]   = 'Opera Mobile';
            $data[1]   = true;
            $data['v'] = $v ?: $data['v'];
        } elseif (isset($this->details['Mini'])) {
            $data[0]   = 'Opera Mini';
            $data['v'] = $this->details['Mini'];
        } elseif ('9.80' == $data['v'] && $v) {
            $data['v'] = $v;
        }
        return $data;
    }

    /**
     * Puffin: https://www.puffinbrowser.com/help/trouble.php#it
     */
    protected function Puffin(array $data, $name)
    {
        if (\preg_match('%\bPuffin[^A-KN-Z\s]+\K[AIW][PTD]%', $this->ua, $match) && isset($this->puffin[$match[0]])) {
            if ('Linux' === $this->result['osName']) {
                $this->result['osName'] = $this->puffin[$match[0]][0];
            }
            $data[1] = $this->puffin[$match[0]][1];
        }
        return $data;
    }

    /**
     * Chrome, Android WebView
     */
    protected function Chrome(array $data, $name)
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
     * IE
     */
    protected function Trident(array $data, $name)
    {
        if (isset($this->trident[$data['v']])) {
            $data['v'] = $this->trident[$data['v']];
            return $data;
        } else {
            return false;
        }
    }

    /**
     * Safari, Android Browser(?), BlackBerry Browser,
     * Samsung Internet: http://developer.samsung.com/internet/user-agent-string-format
     */
    protected function AppleWebKit(array $data, $name)
    {
        $v = $this->getValue('Version', true);

        switch ($this->result['osName']) {
            case 'Android':
                $data[0]   = 'Android Browser';
                $data['v'] = $v;
                break;
            case 'BlackBerry OS':
                $data[0]   = 'BlackBerry Browser';
                $data['v'] = $v;
                break;
            case 'Tizen':
                if (null === $this->getValue('SMART-TV', 'TV')) {
                    $data[0] = 'Tizen Mobile Web Application';
                } else {
                    $data[0] = 'Tizen TV Web Application';
                    $data[1] = false;
                }
                $data['v'] = $v;
                break;
            default:
                if ($v) {
                    $data[0] = 'Safari';
                    $data['v'] = $v;
                }
        }
        return $data;
    }
}

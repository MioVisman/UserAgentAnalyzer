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
    const VERSION = '2.0010';

    const WINNT = [
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

    const WINP = [
        '%^(7|8)(?:\.(\d+))?(?:\.\d+)*$%' => null,
        '%^10(?:\.\d+)*$%'                => [9002, 'win', '10 Mobile'],
    ];

    const REDHAT = [
        '%\.el(\d+)%'  => [null, 'rhel', null],
        '*'            => null,
    ];

    const TRIDENT = [
        '3.1' => [7110, 'iemo', '7.0'],
        '4.0' => [7100, 'msie', '8.0'],
        '5.0' => [7100, 'msie', '9.0'],
        '6.0' => [7100, 'msie', '10.0'],
        '7.0' => [7100, 'msie', '11.0'],
        '8.0' => [7100, 'msie', '11.0'],
        '*'   => null,
    ];

    const GECKO = [
        '%^([12]\d{7})$%'         => null,
        '%^(\d\d?(?:\.\d\d?)+)$%' => [null, null, null, 'handlerFFOS'],
    ];

    const S60 = [
        '0.9' => '6.1',
        '1.2' => '6.1',
        '2.0' => '7.0s',
        '2.1' => '7.0s',
        '2.6' => '8.0a',
        '2.8' => '8.1a',
        '3.0' => '9.1',
        '3.1' => '9.2',
        '3.2' => '9.3',
        '5.0' => '9.4',
        '5.2' => '9.5',
        '5.3' => '10.1',
        '5.4' => '10.1',
        '5.5' => '10.1',
    ];

    protected $ua;
    protected $details;
    protected $result;

    protected $stop = [
        '/' => true,
        ';' => true,
        ')' => true,
        ']' => true,
        ',' => true,
    ];

    protected $pattern = '%\b
        ( [a-z]++ | [A-Z]++ (?: [a-z]++ )? | [\w.]++ )
        (?:
            ( [A-Z]++ (?: [a-z]++ )? | [-_]? (?! [\d_] ) \w+ )
            ( [A-Z]++ (?: [a-z]++ )? | [-_]? (?! [\d_] ) \w+ )?
        )?
        ( \d++ [\w.-]* )?
        (?>
            ( $ | \W )
        )
        (?:
            (?<! [;)\]] )
            (?: [^\w.;)\]-]+ )?
            (?:
                (?: [vV] \.? \ ? )? ( \d++ (?: [._] [\w.-]+ )? )
            |
                (?<= [a-zA-Z] / ) ( [^/\s;()\[\]]+ )
            )
            (?! [\w.-] )
        )?
        %x';

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

    protected $raw = [ //              0     1      2      3     4
        'UCBrowser'              => ['br', 9001, 'ucbr', null,  '%^\d\d?\.\d+%'],
        'UC Browser'             => ['br', 9001, 'ucbr', null,  '%^\d\d?\.\d+%'],
        'UC '                    => ['nx'],
        'UCWEB'                  => ['br', 9000, 'ucbr', null,  ''],
// ?    'U3/'          /* !!! */ =>
// ?    'U2/'          /* !!! */ =>

        'Opera Mobi'             => ['br', 8030, 'opro', null,  null, 'f' => -0.2, 'm' => 100],
        'Opera Mini'             => ['br', 8020, 'opri', true,  '%^\d\d?\.\d+%', 'f' => -0.2, 'm' => 50],
        'Opera '                 => ['br', 8010, 'oper', true,  '%^(\d|1[012])\.(\d+)%', 's' => 'Opera'],
        'Opera/'                 => ['br', 8010, 'oper', true,  '%^(\d|1[012])\.(\d+)%', 's' => 'Opera'],
        'Presto/'      /* !!! */ => ['br', 8000, 'prst', true,  '%^[12](?:\.\d+)*$%', 's' => 'Presto'],

        'SE '                    => ['br', 7900, 'sogo', true,  '%^\d\.[X\d]%'],

        'Avant Browser'          => ['br', 7600, 'avnt', null,  ''],
        'Avant TriCore'          => ['br', 7600, 'avnt', null,  ''],
        'Avant '                 => ['nx'],
        'Maxthon'                => ['br', 7500, 'mxth', null,  '%^\d\.\d%'],
        'MAXTHON'                => ['br', 7500, 'mxth', null,  '%^\d\.\d%'],
        'MxBrowser'              => ['br', 7500, 'mxth', null,  '%^\d\.\d%'],
        'Sleipnir/'              => ['br', 7400, 'slnr', true,  '%^\d\.\d+%'],
        'Lunascape'              => ['br', 7300, 'luna', true,  '%^\d\.\d+%'],
        'EdgA/'                  => ['br', 7150, 'edga', true,  '%^\d\d\.\d+%', 'm' => 100],
        'EdgiOS/'                => ['br', 7140, 'edgi', true,  '%^\d\d\.\d+%', 'm' => 100],
        'Edge/'                  => ['br', 7130, 'edge', true,  '%^1\d\.\d+$%'],
        'MSIEMobile'             => ['br', 7120, 'iemo', true,  '%^6\.\d+%', 'm' => 100],
        'IEMobile'               => ['br', 7110, 'iemo', true,  '%^(6|7|9|1[01])\.(\d+)$%', 'm' => 100],
        'MSIE '                  => ['br', 7100, 'msie', true,  '%^(\d|10)\.(\d+)%'],
        'Trident/'     /* !!! */ => ['br', 7000, 'trnt', true,  self::TRIDENT, 's' => 'Trident'],

        'OmniWeb/'               => ['br', 4400, 'omni', null,  '%^\d\.\d%'],
        'Flock/'                 => ['br', 4300, 'flck', true,  '%^[123]\.\d+%'],
        'Konqueror'              => ['br', 4200, 'knqr', null,  '%^1?\d\.\d+%'],
        'konqueror'              => ['br', 4100, 'knqr', null,  '%^1?\d\.\d+%'],
        'Epiphany/'              => ['br', 4000, 'epph', true,  '%^(\d)\.(\d\d?)(?:\.\d+)*$%'],

        'FBAN/'                  => ['br', 3990, 'fban', true,  ''],

        'coc_coc_browser/'       => ['br', 3700, 'coco', true,  '%^\d\d?\.\d+%'],
        'Silk/'                  => ['br', 3600, 'silk', true,  '%^\d\d?\.\d+%'],
        'Midori/'                => ['br', 3500, 'midr', true,  '%^0\.\d+%'],
        'Comodo_Dragon/'         => ['br', 3400, 'cdrg', true,  '%^\d\d?\.\d+%'],
        'CoolNovo/'              => ['br', 3300, 'novo', true,  '%^[012]\.\d+%'],
        'WebPositive/'           => ['br', 3200, 'wpos', null,  '%^\d\.\d%'],
        'iCab'                   => ['br', 3100, 'icab', true,  '%^(\d)\.(\d)(?:\.\d+)*$%'],
        'OPiOS/'                 => ['br', 3000, 'oios', true,  '%^(\d\d?)\.(\d\d?)(?:\.\d+)*$%'],
        'OPR/'                   => ['br', 2900, 'opr',  true,  '%^(\d\d)\.(\d\d?)(?:\.\d+)*$%'],
        'Chromium/'              => ['br', 2800, 'chmm', true,  '%^(\d\d?)\.(\d\d?)(?:\.\d+)*$%'],
        'CriOS/'                 => ['br', 2700, 'cios', true,  '%^(\d\d?)\.(\d\d?)(?:\.\d+)*$%'],
        'Vivaldi/'               => ['br', 2600, 'viva', true,  '%^(\d)\.(\d\d?)(?:\.\d+)*$%'],
        'YaBrowser/'             => ['br', 2500, 'yabr', true,  '%^(\d\d?)\.(\d\d?)(?:\.\d+)*$%'],
        'QupZilla/'              => ['br', 2400, 'qzll', true,  '%^(\d)\.(\d\d?)(?:\.\d+)*$%'],
        'Iron/'                  => ['br', 2300, 'iron', true,  '%^(\d\d?)\.(\d\d?)(?:\.\d+)*$%'],
        'SamsungBrowser/'        => ['br', 2200, 'ssbr', true,  '%^\d\.\d\d?$%'],
        'Puffin/'                => ['br', 2100, 'pffn', true,  '%^\d\d?\.\d+%', 's' => 'Puffin'],
        'RockMelt/'              => ['br', 2000, 'rkmt', true,  '%^(0|1)\.(\d\d?)(?:\.\d+)*$%'],
        'Chrome/'                => ['br', 1900, 'chrm', true,  '%^(\d\d?)\.(\d\d?)(?:\.\d+)*$%', 's' => 'Chrome'],
        'FxiOS/'                 => ['br', 1800, 'fios', true,  '%^\d\d?\.\d\d?b?%'],
        'Arora/'                 => ['br', 1700, 'aror', true,  '%^0\.\d+%'],
        'Otter/'                 => ['br', 1600, 'ottr', true,  '%^\d\.\d+%'],
        'Dooble/'                => ['br', 1500, 'dble', true,  '%^\d\.\d+%'],
        'NokiaBrowser/'          => ['br', 1400, 'nobr', true,  '%^[78]\.\d+%', 'm' => 100],
        'BrowserNG/'             => ['br', 1300, 'nobr', true,  '%^[78]\.\d+%', 'm' => 100],
        'Dolfin/'                => ['br', 1200, 'dlfn', true,  '%^(\d|1[01])\.(\d\d?)%'],
        'wOSBrowser'             => ['br', 1100, 'wsbr', null,  null],
        'AppleWebKit/' /* !!! */ => ['br', 1000, 'wbkt', true,  '%^(\d{2,3})(?:$|\.(\d+))%', 's' => 'WebKit'],

        'PaleMoon/'              => ['br',  910, 'plmn', true,  '%^\d\d?\.\d+%'],
        'Goanna/'      /* !!! */ => ['br',  900, 'goan', true,  '%^\d{8}|\d\d?(?:\.\d\d?)+$%', 's' => 'Goanna'],

        'S40OviBrowser/'         => ['br',  700, 'ovib', true,  '%^\d\.\d+%'],

        'Maemo Browser '         => ['br',  600, 'mmbr', true,  '%^\d\.\d+%'],
        'Galeon/'                => ['br',  500, 'galn', true,  '%^[12]\.\d+%'],
        'IceCat/'                => ['br',  451, 'icat', true,  '%^\d\d?\.\d+%'],
        'Iceweasel/'             => ['br',  450, 'icwl', true,  '%^\d\d?\.\d+%'],
        'K-Meleon/'              => ['br',  400, 'kmln', true,  '%^\d\d?\.\d+%'],
        'SeaMonkey/'             => ['br',  350, 'smnk', true,  '%^[12]\.\d+%'],
        'Camino/'                => ['br',  300, 'cami', true,  '%^[012]\.\d+%'],
        'Conkeror/'              => ['br',  260, 'conk', true,  '%^[01]\.\d+%'],
        'conkeror/'              => ['br',  260, 'conk', true,  '%^[01]\.\d+%'],
        'Fennec/'                => ['br',  250, 'fnnc', true,  '%^\d\d?\.\d\d?b?%'],
        'Firefox/'               => ['br',  200, 'frfx', true,  '%^\d\d?\.\d+%'],
        'Gecko/'       /* !!! */ => ['br',  150, 'geck', true,  self::GECKO, 's' => 'Gecko'],

        'KHTML/'       /* !!! */ => ['br',  100, 'ktml', true,  '%^(\d\d?)(?:\.(\d\d?)(?:\.(\d\d?))?)?$%', 's' => 'KHTML'],

        'NetPositive'            => ['br',   80, 'npos', null,  null],
        'Emacs-w3m'              => ['br',   70, 'ew3m', true,  '%^1\.\d%'],
        'w3m'                    => ['br',   60, 'w3m',  true,  '%^0\.[\dx]%'],
        'Lynx'                   => ['br',   50, 'lunx', null,  '%^[012]\.\d+%'], // ?
        'Links'                  => ['br',   40, 'lnks', null,  '%^[012]\.\d?\d?x?%'],
        'ELinks'                 => ['br',   30, 'elnk', null,  '%^0\.\d+%'],
        'NetSurf/'               => ['br',   20, 'nsrf', true,  '%^[0-3]\.\d$%'],
        'NetFront/'              => ['br',   10, 'nfrt', true,  '%^[1-4]\.\d+%'],
        'CFNetwork/'             => ['br',    5, 'cfnw', true,  null],
        'Mozilla'                => ['br',    0, 'mzll', true,  '%^[0-5]\.\d\d?$%'],
        'Safari'                 => ['br',    0, 'wbkt', true,  '%^(\d{2,3})(?:$|\.(\d+))%'],

        'Windows NT '            => ['os', 9002, 'win',  true,  self::WINNT, 'f' => -0.2],
        'Windows CE;'            => ['os', 9001, 'winc', null,  null, 'f' => -0.2, 'm' => 100],
        'Windows Mobile'         => ['os', 9001, 'winm', null,  null, 'f' => -0.2, 'm' => 100],
        'Windows Phone '         => ['os', 9001, 'winp', true,  self::WINP, 'f' => -0.2, 'm' => 100],
        'Windows Phone OS'       => ['os', 9001, 'winp', true,  self::WINP, 'f' => -0.2, 'm' => 100],
        'Windows '               => ['os', 9000, 'win',  true,  '%^95|98$%'],
        'Win '                   => ['nx'],
        'Win 9x '                => ['os', 9000, 'win',  true,  ['4.90' => 'ME']],
        'Win98;'                 => ['os', 9000, 'win',  false, '98'],
        'Win95;'                 => ['os', 9000, 'win',  false, '95'],
        'Windows;'               => ['os', 8999, 'win',  false, null],
        'MorphOS'                => ['os', 8902, 'morp', null,  '%^(\d)(?:\.(\d+))?%'],
        'AROS'                   => ['os', 8901, 'aros', null,  '%^(\d)(?:\.(\d+))?%'],
        'AmigaOS'                => ['os', 8900, 'amos', null,  '%^(\d)(?:\.(\d+))?%'],
        'iPhone;'                => ['os', 8011, 'ios',  false, null, 'm' => 100],
        'iPad;'                  => ['os', 8011, 'ios',  false, null, 'm' => 100],
        'iPod;'                  => ['os', 8011, 'ios',  false, null, 'm' => 100],
        'CPU '                   => ['nx'],
        'CPU iPhone '            => ['nx'],
        'CPU iPhone OS '         => ['os', 8011, 'ios',  true, '%^(1?\d)[._](\d\d?)(?:[._]\d\d?)?$%'],
        'CPU OS '                => ['os', 8011, 'ios',  true, '%^(1?\d)[._](\d\d?)(?:[._]\d\d?)?$%'],
        'Mac '                   => ['nx'],
        'Mac OS '                => ['os', 8010, 'mac',  true, '%^(1?\d)[._](\d\d?)(?:[._]\d\d?)?$%'],
        'Mac OS X '              => ['os', 8010, 'osx',  true, '%^(1?\d)[._](\d\d?)(?:[._]\d\d?)?$%', 'f' => -0.2],
        'Mac OS X;'              => ['os', 8010, 'osx',  false, null, 'f' => -0.2],
        'Mac OS X Mach-O;'       => ['os', 8010, 'osx',  false, null, 'f' => -0.2],
        'Darwin/'                => ['os', 8001, 'darw', true,  null],
        'Macintosh;'             => ['os', 8000, 'mac',  null,  null],
        'Mac_PowerPC'            => ['os', 8000, 'mac',  null,  null],
        'Tizen '                 => ['os', 7500, 'tizn', true, '%^\d\.\d%', 'm' => 100],
        'Tizen;'                 => ['os', 7500, 'tizn', false, null, 'm' => 100],
        'webOS/'                 => ['os', 7250, 'wbos', true, '%^\d\.\d%', 'm' => 100],
        'hpwOS/'                 => ['os', 7250, 'wbos', true, '%^\d\.\d%', 'm' => 100],
        'hpwOS '                 => ['os', 7250, 'wbos', true, '%^\d\.\d%', 'm' => 100],
        'Android;'               => ['os', 7000, 'andr', false, null, 'm' => 100],
        'Android '               => ['os', 7000, 'andr', true, '%^\d\.\d%', 'm' => 100],
        'Adr '                   => ['os', 7000, 'andr', true, '%^\d\.\d%', 'm' => 100],
        'RemixOS'                => ['os', 6000, 'remx', null,  null],
        'CrOS'                   => ['os', 5000, 'cros', null,  null],
        'Sailfish'               => ['os', 2600, 'sfsh', null,  null],
        'ArchLinux'              => ['os', 2500, 'arch', null,  null],
        'Arch;'                  => ['os', 2500, 'arch', false, ''],
        'Arch'                   => ['nx'],
        'CentOS'                 => ['os', 2400, 'cnos', null,  '%\.el(\d+)[^\s;/]*\.centos%'],
        'SUSE'                   => ['os', 2300, 'suse', null,  ''],
        'openSUSE'               => ['os', 2300, 'suse', null,  '%^\d\d\.\d%'],
        'Fedora'                 => ['os', 2200, 'fdra', null,  '%\.fc(\d+)%'],
        'LinuxMint'              => ['os', 2100, 'mint', null,  null],
        'Kubuntu'                => ['os', 2000, 'kbnt', null,  null],
        'Xubuntu'                => ['os', 2000, 'xbnt', null,  null],
        'Ubuntu'                 => ['os', 1900, 'ubnt', null,  null],
        'Mageia'                 => ['os', 1870, 'mgia', null,  '%^(\d)(?:\.(\d\d?))?%'], // ? mga
        'PCLinuxOS'              => ['os', 1860, 'pclx', null,  '%pclos(\d+)(?:\.(\d\d?))?%'],
        'Mandriva/'              => ['os', 1850, 'mndv', null,  '%m(?:dv|ib)(\d+)\.(\d)%'],
        'Mandriva Linux'         => ['os', 1850, 'mndv', null,  '%m(?:dv|ib)(\d+)\.(\d)%'],
        'Mandriva '              => ['nx'],
        'Red HatEnterpriseLinux' => ['os', 1801, 'rhel', null,  '%\.el(\d+)%'],
        'Red HatEnterprise'      => ['os', 1801, 'rhel', null,  '%\.el(\d+)%'],
        'Red Hat'                => ['os', 1800, 'rhat', null,  self::REDHAT],
        'Red '                   => ['nx'],
        'Maemo '                 => ['os', 1750, 'maem', null,  null, 'm' => 100],
        'Maemo;'                 => ['os', 1750, 'maem', false, '', 'm' => 100],
        'Debian'                 => ['os', 1700, 'debn', null,  null],
        'Slackware'              => ['os', 1600, 'slwa', null,  null],
        'MeeGo'                  => ['os', 1500, 'mego', null,  null, 'm' => 50],
        'Linux'                  => ['os', 1250, 'lnux', null,  null],
        'DragonFly'              => ['os', 1010, 'dfly', null,  null],
        'FreeBSD'                => ['os', 1000, 'fbsd', null,  null],
        'NetBSD'                 => ['os', 1000, 'ndsd', null,  null],
        'OpenBSD'                => ['os', 1000, 'obsd', null,  null],
        'BrewMP'                 => ['os',  851, 'brmp', null,  '%^\d\.\d+%', 'm' => 100],
        'Brew'                   => ['os',  850, 'brew', null,  '%^\d\.\d+%', 'm' => 100],
        'BREW'                   => ['os',  850, 'brew', null,  '%^\d\.\d+%', 'm' => 100],
        'Haiku'                  => ['os',  810, 'haik', null,  null],
        'BeOS'                   => ['os',  800, 'beos', null,  null],
        'Bada/'                  => ['os',  750, 'bada', true,  '%^[12]\.\d%', 'm' => 50],
        'Bada;'                  => ['os',  750, 'bada', false, null, 'm' => 50],
        'BB10;'                  => ['os',  500, 'bbos', false, '10', 'm' => 100],
        'BlackBerry'             => ['os',  500, 'bbos', null,  '%(?<!\d)([1-7]\.\d+)%', 'm' => 100],
        'Series90/'              => ['os',  262, 's90',  true,  '%^\d\.\d$%', 'm' => 100],
        'Series80/'              => ['os',  261, 's80',  true,  '%^[12]\.\d$%', 'm' => 100],
        'Series30Plus'           => ['os',  260, 's30p', null,  '', 'm' => 100],
        'SymbianOS'              => ['os',  252, 'symb', true,  '%^1?\d\.\d[as]?$%', 'm' => 100],
        'Series60/'              => ['os',  251, 'symb', true,  self::S60, 'm' => 100],
        'SymbOS;'                => ['os',  250, 'symb', false, '', 'm' => 100],
        'SymbianOS;'             => ['os',  250, 'symb', false, '', 'm' => 100],
        'Symbian'                => ['os',  250, 'symb', null,  '', 'm' => 100],
        'KAIOS/'                 => ['os',  200, 'kaos', true,  '%^\d\.\d+%', 'm' => 100],
        'KaiOS/'                 => ['os',  200, 'kaos', true,  '%^\d\.\d+%', 'm' => 100],
        'J2ME/'                  => ['os',  100, 'java', true,  '%^(?=MIDP)%', 'm' => 50],
        'Profile/'               => ['os',  100, 'java', true,  '%^(?=MIDP)%', 'm' => 50],
        'Configuration/'         => ['os',  100, 'java', true,  '%^(?=CLDC)%', 'm' => 50],
        'SunOS'                  => ['os',   60, 'snos', null,  ''],
        'AIX '                   => ['os',   55, 'aix',  null,  '%^([1-7])(?:$|\.(\d))%'],
        'X11;'                   => ['os',   50, 'unix', false, null],

        'Mobile'                 => ['', 'm' => 100],
        'Version/'               => ['', 's' => 'Version'],
        'wv)'                    => ['', 's' => 'wv'],
        'rv:'                    => ['', 's' => 'rv'],
        'SMART-TV'               => ['', 's' => 'SMART-TV'],

        'BingPreview'            => ['ro', 'BingPreview'],
        'Mediapartners-Google'   => ['ro', 'Google AdSense'],
        'YandexBlogs'            => ['ro', 'YandexBlogs'],
        'FlipboardProxy'         => ['ro', 'FlipboardProxy'],
        'FlipboardBrowserProxy'  => ['ro', 'FlipboardProxy'],
        'Prerender'              => ['ro', 'Prerender'],
        'googleweblight'         => ['ro', 'GoogleWebLight'], // ?
        'Yahoo'                  => ['nx'],
        'YahooSlurp'             => ['ro', 'Yahoo! Slurp'],
        'YahooAd'                => ['ro', 'Yahoo Ad monitoring'],
        'Daum'                   => ['ro', 'Daum'],
        'elefent'                => ['ro', 'Elefent'],
        'GigablastOpenSource'    => ['ro', 'Gigabot'],
        'Qwantify'               => ['ro', 'Qwantify'],
        'YahooCacheSystem'       => ['ro', 'YahooCacheSystem'],
        'Applebot'               => ['ro', 'Applebot'],
        'Dataprovider'           => ['ro', 'Dataprovider'],
    ];

    protected $alias = [
        'adbr' => 'Android Browser',
        'adwv' => 'Android WebView',
        'aror' => 'Arora',
        'avnt' => 'Avant Browser',
        'bbbr' => 'BlackBerry Browser',
        'cami' => 'Camino',
        'cfnw' => 'CFNetwork',
        'chrm' => 'Chrome',
        'cios' => 'Chrome for iOS',
        'chmm' => 'Chromium',
        'coco' => 'Coc Coc',
        'cdrg' => 'Comodo Dragon',
        'conk' => 'Conkeror',
        'novo' => 'CoolNovo',
        'dlfn' => 'Dolfin',
        'dble' => 'Dooble',
        'elnk' => 'ELinks',
        'ew3m' => 'Emacs-w3m',
        'epph' => 'Epiphany',
        'fban' => 'Facebook App',
        'frfx' => 'Firefox',
        'fios' => 'Firefox for iOS',
        'fnnc' => 'Firefox Mobile',
        'flck' => 'Flock',
        'galn' => 'Galeon',
        'haik' => 'Haiku',
        'icab' => 'iCab',
        'icat' => 'IceCat',
        'icwl' => 'Iceweasel',
        'msie' => 'Internet Explorer',
        'iemo' => 'Internet Explorer Mobile',
        'kmln' => 'K-Meleon',
        'knqr' => 'Konqueror',
        'lnks' => 'Links',
        'luna' => 'Lunascape',
        'lunx' => 'Lynx',
        'mxth' => 'Maxthon',
        'mmbr' => 'MicroB',
        'edga' => 'Microsoft Edge for Android',
        'edgi' => 'Microsoft Edge for iOS',
        'edge' => 'Microsoft Edge',
        'midr' => 'Midori',
        'mzll' => 'Mozilla', // ?
        'nfrt' => 'NetFront',
        'npos' => 'NetPositive',
        'nsrf' => 'NetSurf',
        'nobr' => 'Nokia Browser',
        'ovib' => 'Nokia Ovi Browser',
        'omni' => 'OmniWeb',
        'oper' => 'Opera',
        'opr'  => 'Opera',
        'oios' => 'Opera for iOS',
        'opri' => 'Opera Mini',
        'opro' => 'Opera Mobile',
        'ottr' => 'Otter Browser',
        'plmn' => 'Pale Moon',
        'pffn' => 'Puffin',
        'qzll' => 'QupZilla',
        'rkmt' => 'RockMelt',
        'sfri' => 'Safari',
        'ssbr' => 'Samsung Internet',
        'smnk' => 'SeaMonkey',
        'sogo' => 'Sogou',
        'silk' => 'Amazon Silk',
        'slnr' => 'Sleipnir',
        'iron' => 'SRWare Iron',
        'tzmo' => 'Tizen Mobile Web Application',
        'tztv' => 'Tizen TV Web Application',
        'ucbr' => 'UC Browser',
        'uiwv' => 'UIWebView',
        'viva' => 'Vivaldi',
        'w3m'  => 'w3m',
        'wsbr' => 'webOS Browser',
        'wpos' => 'WebPositive',
        'yabr' => 'Yandex Browser',

        'geck' => 'Gecko (layout engine)',
        'goan' => 'Goanna (layout engine)',
        'prst' => 'Presto (layout engine)',
        'trnt' => 'Trident (layout engine)',
        'wbkt' => 'WebKit (layout engine)',

        'aix'  => 'AIX',
        'amos' => 'AmigaOS',
        'andr' => 'Android',
        'arch' => 'Arch Linux',
        'aros' => 'AROS',
        'bada' => 'Bada',
        'bbos' => 'BlackBerry OS',
        'beos' => 'BeOS',
        'brew' => 'Brew',
        'brmp' => 'Brew MP',
        'cnos' => 'CentOS',
        'cros' => 'Chrome OS',
        'darw' => 'Darwin',
        'debn' => 'Debian',
        'dfly' => 'DragonFly BSD',
        'fdra' => 'Fedora',
        'ffos' => 'Firefox OS',
        'fbsd' => 'FreeBSD',
        'ios'  => 'iOS',
        'java' => 'Java',
        'kaos' => 'KaiOS',
        'kbnt' => 'Kubuntu',
        'lnux' => 'Linux',
        'mint' => 'Linux Mint',
        'mac'  => 'Mac',
        'osx'  => 'Mac OS X',
        'maem' => 'Maemo',
        'mndv' => 'Mandriva Linux',
        'mgia' => 'Mageia',
        'mego' => 'MeeGo',
        'morp' => 'MorphOS',
        'ndsd' => 'NetBSD',
        'obsd' => 'OpenBSD',
        'suse' => 'openSUSE',
        'pclx' => 'PCLinuxOS',
        'rhat' => 'Red Hat',
        'rhel' => 'Red Hat Enterprise Linux',
        'remx' => 'Remix OS',
        'sfsh' => 'Sailfish OS',
        's30p' => 'Series 30+',
        's80'  => 'Series 80',
        's90'  => 'Series 90',
        'slwa' => 'Slackware',
        'snos' => 'Solaris',
        'symb' => 'Symbian OS',
        'tizn' => 'Tizen',
        'ubnt' => 'Ubuntu',
        'unix' => 'Unix',
        'wbos' => 'webOS',
        'win'  => 'Windows',
        'winc' => 'Windows CE',
        'winm' => 'Windows Mobile',
        'winp' => 'Windows Phone',
        'xbnt' => 'Xubuntu',
    ];

    protected $fix = [
        'andrchrm' => 'fixAndroidWV',
        'andrwbkt' => 'fixAndroidBR',
        'bbos'     => 'fixBBBR',
        'bboswbkt' => 'fixBBBRkit',
        'lnuxchrm' => 'fixLinuxWV',
        'lnuxpffn' => 'fixPuffinOS',
        'tiznwbkt' => 'fixTizenBR',
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

    protected $puffin = [
        'IP' => ['ios',  100],
        'IT' => ['ios',  100],
        'AP' => ['andr', 100],
        'AT' => ['andr', 100],
        'WP' => ['winp', 100],
        'WD' => ['win',  0],
    ];

    protected $botSize;
    protected $botTest = [
        'crawl'   => [100, null],
        'nutch'   => [100, null],
        'bot'     => [100, '%(?<!cu)bot(?!tle)%'],
        'spider'  => [100, '%spider(?![\w\ ]*build/)%'],
        'google'  => [100, '%google(?:w|\ |;|\-(?!tr))%'],
        'preview' => [ 50, null],
        'search'  => [ 40, null],
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

        $botCheck      = [];
        $uaLC          = \strtolower($ua);
        $uaIn          = $ua;
        $this->ua      = $ua;
        $this->botSize = 0;
        $this->result  = [
            'isMobile'       => null,
            'isRobot'        => null,
            'botName'        => null,
            'botVersion'     => null,
            'browserName'    => null,
            'browserVersion' => null,
            'osName'         => null,
            'osVersion'      => null,
        ];

        foreach ($this->botTest as $key => $info) {
            $pos = \strpos($uaLC, $key);
            if (false !== $pos
                && (null === $info[1] || \preg_match($info[1], $uaLC))
            ) {
                $this->botSize += $info[0];
                $botCheck[$key] = $pos;
            }
        }

        if (false !== \strpos($uaLC, 'http')) {
            $uaIn = \preg_replace('%https?:[^);\s]*[);]?%i', ' ', $uaIn, -1, $count);
            $this->botSize += 40 * $count;
        }
        if (false !== \strpos($uaIn, 'www.')) {
            $uaIn = \preg_replace('%www\.[^);\s]*[);]?%i', ' ', $uaIn, -1, $count);
            $this->botSize += 40 * $count;
        }
        if (false !== \strpos($uaIn, '@')) {
            $uaIn = \preg_replace('%[^\s/;()@]+@[^);\s]*[);]?%i', ' ', $uaIn, -1, $count);
            $this->botSize += 40 * $count;
        }
        if (false !== \strpos($uaLC, 'like')) {
            $uaIn = \preg_replace('%\blike[^,;)]*%i', '', $uaIn);
        }

        $data = $this->details($uaIn);

        if ($this->botSize < 100) {
            if (isset($this->alias[$data['os'][1]])) {
                $this->result['osName']    = $this->alias[$data['os'][1]];
                $this->result['osVersion'] = $data['os'][2];
            } else {
                $this->botSize += 60;
            }
            if ($this->botSize < 100) {
                if (isset($this->alias[$data['br'][1]])) {
                    $this->result['browserName']    = $this->alias[$data['br'][1]];
                    $this->result['browserVersion'] = $data['br'][2];
                } else {
                    $this->botSize += 30;
                }
                if ($this->botSize < 100) {
                    $this->result['isMobile'] = $data['m'] >= 100;

                    return $this->result;
                }
            }
        }

        $this->result['isRobot'] = true;

        if (\is_string($data)) {
            $data = \explode('|', $data, 2);
            $this->result['botName'] = $data[0];
            if (isset($data[1]{0})) {
                $this->result['botVersion'] = $data[1];
            }
            return $this->result;
        }

        \asort($botCheck, \SORT_NUMERIC);

        foreach ($botCheck as $key => $size) {
            if (\preg_match('%\b[^;()]*' . $key . '[\w\ .!-]*%i', $uaIn, $match)) {
                $uaIn = $match[0];
                break;
            }
        }
        if (empty($match[0])) {
            $uaIn = \preg_replace('%Mozilla.*?compatible[); ]*%i', ' ', $uaIn);
            $uaIn = \preg_replace('%DoCoMo.*?compatible[); ]*%i', ' ', $uaIn);
        }

        $uaIn = \trim(\preg_replace($this->clean, ' ', $uaIn), ' ._-');
        $len  = \strlen($uaIn);

        if ($len < 3 || $len > 30 || \count(\preg_split('%[ ._-]%', $uaIn)) > 4) {
            $uaIn = null;
        } elseif (\preg_match('%' . \preg_quote($uaIn, '%'). '[v /.-]*(\d+(\.[x\d]+)*)%i', $ua, $match)) {
            $this->result['botVersion'] = $match[1];
        }

        $this->result['botName'] = $uaIn;

        return $this->result;
    }

    protected function details($ua)
    {
        \preg_match_all($this->pattern, $ua, $matches, \PREG_SET_ORDER);

        $data = [
            'f'  => 0,
            'm'  => 0,
            'br' => [-1, null, null],
            'os' => [-1, null, null],
        ];
        $prev = '';

        foreach ($matches as $m) {
            $name = null;

            do {
                $tmp  = $prev . $m[1];

                if (isset($m[5]{0}, $this->raw[$tmp . $m[2] . $m[3] . $m[4] . $m[5]])) {
                    $name   = $tmp . $m[2] . $m[3] . $m[4] . $m[5];
                    $v4     = false;
                    $ending = '';
                    break;
                } elseif (isset($m[4]{0}, $this->raw[$tmp . $m[2] . $m[3] . $m[4]])) {
                    $name   = $tmp . $m[2] . $m[3] . $m[4];
                    $v4     = false;
                    $ending = '';
                    break;
                } elseif (isset($m[3]{0}, $this->raw[$tmp . $m[2] . $m[3]])) {
                    $name   = $tmp . $m[2] . $m[3];
                    $v4     = true;
                    $ending = '';
                    break;
                } elseif (isset($m[2]{0}, $this->raw[$tmp . $m[2]])) {
                    $name   = $tmp . $m[2];
                    $v4     = true;
                    $ending = $m[3];
                    break;
                } elseif (isset($this->raw[$tmp])) {
                    $name   = $tmp;
                    $v4     = true;
                    $ending = $m[2] . $m[3];
                    break;
                }
            } while (isset($prev{0}) && ! $prev = '');

            if (null === $name) {
                continue;
            }

            $raw = $this->raw[$name];

            if (isset($raw['f'])) {
                $data['f'] += $raw['f'];
            }

            if (isset($raw['m'])) {
                $data['m'] += $raw['m'];
            }

            if ($v4 && isset($m[4]{0})) {
                $version = $m[4];
                $tmp     = $m[5];
            } else {
                $version = null;
                $tmp     = '';
            }
            if (isset($m[6]{0})) {
                $version .= $tmp . $m[6];
            } elseif (isset($m[7]{0})) {
                $version .= $tmp . $m[7];
            }

            if (isset($version{0}) || isset($this->stop[$m[5]])) {
                $prev = '';
            } else {
                $prev = $name;
            }

            if (isset($ending{0}) && empty($raw['ending'])) {
                $prev = '';
                $data['f'] += 0.1;
                continue;
            }

            if (isset($raw['s'])) {
                $this->details[$raw['s']] = (string) $version;
            }

            switch ($raw[0]) {
                case 'ro':
                    $this->botSize = 100;
                    return $raw[1] . '|' . $version;
                case 'br':
                case 'os':
                    $type = $raw[0];
                    break;
                default:
                    continue 2;
            }

            if (null === $version && true === $raw[3]) {
                $data['f'] += 0.2;
                continue;
            } elseif (false === $raw[3] && isset($version)) {
                $data['f'] += 0.1;
            }

            if (isset($raw[4]{0}) && '%' === $raw[4]{0}) {
                $vs = [
                    $raw[4] => null,
                ];
            } else {
                $vs = $raw[4];
            }

            $merge = null;

            if (null === $vs) {
                $ver = $version;
            } elseif (\is_array($vs)) {
                $ver = null;

                foreach ($vs as $key => $val) {
                    if ('*' === $key) {
                        $ver   = $version;
                        $merge = $val;
                        break;
                    } elseif ('%' === $key{0}) {
                        if (\preg_match($key, $version, $match)) {
                            if (isset($match[1])) {
                                unset($match[0]);
                                $ver = \implode('.', $match);
                            } else {
                                $ver = $match[0];
                            }
                            $merge = $val;
                            break;
                        }
                    } elseif ($key == $version) { // ?
                        $merge = $val;
                        break;
                    }
                }
            } else {
                $ver = $vs;
            }

            if (\is_string($merge)) {
                $ver = $merge;
            } elseif (\is_array($merge)) {
                if (isset($merge[3])) { // handler
                    $data = $this->{$merge[3]}($data, $ver);
                }
                if (isset($merge[2])) { // version
                    $ver = $merge[2];
                }
                if (isset($merge[1])) { // code
                    $raw[2] = $merge[1];
                }
                if (isset($merge[0])) { // weight
                    $raw[1] = $merge[0];
                }
            }

            if (null === $ver && true === $raw[3]) {
                $data['f'] += 0.2;
                continue;
            }

            if ($raw[1] >= $data[$type][0]) {
                $data[$type][0] = $raw[1];

                if (isset($ver{0}) || $data[$type][1] !== $raw[2]) {
                    $data[$type][2] = $ver;
                }

                $data[$type][1] = $raw[2];
            }
        }

        $fix = $data['os'][1] . $data['br'][1];

        if (isset($this->fix[$fix])) {
            $data = $this->{$this->fix[$fix]}($data);
        }

        foreach (['br', 'os'] as $type) {
            if (isset($data[$type][1])
                && \method_exists($this, $data[$type][1])
            ) {
                $data = $this->{$data[$type][1]}($data);
            }
        }

        return $data;
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
     * set Firefox OS
     */
    protected function handlerFFOS(array $data, $version)
    {
        if (empty($data['os'][1]) && ! empty($this->details['rv']) && isset($this->firefoxos[$version])) {
            $data['os'][1] = 'ffos';
            $data['os'][2] = $this->firefoxos[$version];
        }
        return $data;
    }

    /**
     * fix BlackBerry OS -> BlackBerry Browser
     */
    protected function fixBBBR(array $data)
    {
        $data['br'][1] = 'bbbr';
        $data['br'][2] = $data['os'][2];
        return $data;
    }

    /**
     * fix WebKit -> BlackBerry Browser
     */
    protected function fixBBBRkit(array $data)
    {
        $data['br'][1] = 'bbbr';
        $data['br'][2] = isset($this->details['Version']) ? $this->details['Version'] : null;
        return $data;
    }

    /**
     * fix Chrome -> Android WebView
     */
    protected function fixAndroidWV(array $data) {
        if (! empty($this->details['Version'])) {
            $data['br'][1] = 'adwv';
            $data['br'][2] = $this->details['Version'];
        } elseif (isset($this->details['wv'])) {
            $data['br'][1] = 'adwv';
            $data['br'][2] = null;
        }
        return $data;
    }

    /**
     * fix Chrome -> Android WebView
     */
    protected function fixLinuxWV(array $data) {
        if (! empty($this->details['Version'])) {
            $data['br'][1] = 'adwv';
            $data['br'][2] = $this->details['Version'];
            $data['f']    += 0.1;
            $data['os'][1] = 'andr';
            $data['os'][2] = null;
        } elseif (isset($this->details['wv'])) {
            $data['br'][1] = 'adwv';
            $data['br'][2] = null;
            $data['f']    += 0.1;
            $data['os'][1] = 'andr';
            $data['os'][2] = null;
        }
        return $data;
    }

    /**
     * fix Linux -> iOS, Android or Windows
     */
    protected function fixPuffinOS(array $data)
    {
        if (\preg_match('%[AIW][PTD]%', $this->details['Puffin'], $match) && isset($this->puffin[$match[0]])) {
            $data['os'][1] = $this->puffin[$match[0]][0];
            $data['os'][2] = null;
            $data['m']     = $this->puffin[$match[0]][1];
        }
        return $data;
    }

    /**
     * fix WebKit -> Android Browser ?
     */
    protected function fixAndroidBR(array $data)
    {
        $data['br'][1] = 'adbr';
        $data['br'][2] = isset($this->details['Version']) ? $this->details['Version'] : null;
        return $data;
    }

    /**
     * fix WebKit -> Tizen Mobile/TV Web Application
     */
    protected function fixTizenBR(array $data)
    {
        if (null === $this->getValue('SMART-TV', 'TV')) {
            $data['br'][1] = 'tzmo';
        } else {
            $data['br'][1] = 'tztv';
            $data['m']     = 0;
        }
        $data['br'][2] = isset($this->details['Version']) ? $this->details['Version'] : null;
        return $data;
    }


    /**
     * Chrome OS
     */
    protected function cros(array $data)
    {
        if (isset($this->details['Chrome'])) {
            if (\preg_match('%^\d\d?\.\d\d?%', $this->details['Chrome'], $match)) {
                $data['os'][2] = $match[0];
            }
        } else {
            $data['f'] += 0.5;
        }
        return $data;
    }

    /**
     * Opera
     */
    protected function oper(array $data)
    {
        if (isset($this->details['Version'])) {
            if ($this->details['Version'] >= 10 && $this->details['Version'] < 13) {
                $data['br'][2] = $this->details['Version'];
            } else {
                $data['f'] += 0.5;
            }
        }
        return $data;
    }

    /**
     * Opera Mobi
     */
    protected function opro(array $data)
    {
        $v = $this->getValue('Version', 'Opera', true);
        if ($v < 13) { // NULL in $v
            $data['br'][2] = $v;
        } else {
            $data['f']    += 0.5;
            $data['br'][2] = null;
        }
        return $data;
    }

    /**
     * Safari, UIWebView
     */
    protected function wbkt(array $data)
    {
        if (! empty($this->details['Version'])) {
            $data['br'][1] = 'sfri';
            $data['br'][2] = $this->details['Version'];
        } elseif ('ios' === $data['os'][1]) {
            $data['br'][1] = 'uiwv';
            $data['br'][2] = null;
        }
        return $data;
    }
}

/*
Sub Store 规则配置脚本
版本: 1.1.0
更新时间：2024-12-25
脚本功能: 
 - Sub Store 处理订阅源，为 Clash、Clash.Meta、Stash 格式订阅添加完整的规则配置
 - 自动分类并组织代理节点
 - 配置代理分流规则
 - 设置 DNS 解析策略

订阅源 -> 基础解析 -> 格式特定转换 -> 输出
                        ↑
                     脚本在这里执行

Sub-Store项目地址: https://github.com/sub-store-org/Sub-Store
用法: 添加到Sub Store的脚本操作中
说明: 添加规则配置、代理组配置、DNS配置等

参数说明:
- proxyName: 默认代理组名称
- customRules: 自定义规则列表
*/

// 全局变量
const scriptName = "Sub-Store Rules";
const version = "1.1.0";
const proxyName = "代理模式";

// 获取脚本参数
const inArg = $arguments || {};

// 正则表达式定义
const regexConfig = {
    // 需要删除的节点关键词
    removeNodes: /套餐|到期|有效|剩余|版本|已用|过期|失联|测试|官方|网址|备用|群|TEST|客服|网站|获取|订阅|流量|机场|下次|官址|联系|邮箱|工单|学术|USE[D]?|TOTAL|EXPIRE|EMAIL/i,
    
    // 倍率匹配
    multiplier: /(?:\d+(?:\.\d+)?)[xX×]|[xX×](?:\d+(?:\.\d+)?)/,
    
    // 地区匹配
    regions: {
        HK: /^(?:香港|HK|Hong Kong|🇭🇰)/i,
        SG: /^(?:新加坡|狮城|SG|Singapore|🇸🇬)/i,
        JP: /^(?:日本|JP|Japan|🇯🇵)/i,
        US: /^(?:美国|US|United States|🇺🇸)/i,
        TW: /^(?:台湾|TW|Taiwan|🇹🇼)/i,
        KR: /^(?:韩国|KR|Korea|🇰🇷)/i
    },
    
    // 特殊标识
    specialTags: /IPLC|IEPL|BGP|RELAY|PREMIUM|PLUS|PRO|GAME/i,
    
    // 数字序号
    number: /\s*(?:[0-9]{1,2}|[0-9]{1,2}\.[0-9]{1,2})\s*$/,

    // 地区替换规则
    regionReplace: {
        GB: /UK/g,
        "B-G-P": /BGP/g,
        "Russia Moscow": /Moscow/g,
        "Korea Chuncheon": /Chuncheon|Seoul/g,
        "Hong Kong": /Hongkong|HONG KONG/gi,
        "United Kingdom London": /London|Great Britain/g,
        "Dubai United Arab Emirates": /United Arab Emirates/g,
        "Taiwan TW 台湾 🇹🇼": /(台|Tai\s?wan|TW).*?🇨🇳|🇨🇳.*?(台|Tai\s?wan|TW)/g,
        "United States": /USA|Los Angeles|San Jose|Silicon Valley|Michigan/g,
        澳大利亚: /澳洲|墨尔本|悉尼|土澳|(深|沪|呼|京|广|杭)澳/g,
        德国: /(深|沪|呼|京|广|杭)德(?!.*(I|线))|法兰克福|滬德/g,
        香港: /(深|沪|呼|京|广|杭)港(?!.*(I|线))/g,
        日本: /(深|沪|呼|京|广|杭|中|辽)日(?!.*(I|线))|东京|大坂/g,
        新加坡: /狮城|(深|沪|呼|京|广|杭)新/g,
        美国: /(深|沪|呼|京|广|杭)美|波特兰|芝加哥|哥伦布|纽约|硅谷|俄勒冈|西雅图|芝加哥/g
    }
};

// 主函数
function main(params) {
    try {
        console.log(`${scriptName} v${version} 开始处理...`);
        
        // 参数检查
        if (!params || !params.proxies || params.proxies.length === 0) {
            throw new Error('节点列表为空');
        }

        // 清理无效节点
        params.proxies = cleanNodes(params.proxies);
        
        // 添加规则配置
        addRules(params);
        // 添加代理组配置
        addProxyGroups(params);
        // 添加DNS配置
        addDns(params);

        console.log('处理完成');
        return params;
    } catch (err) {
        console.log(`处理失败: ${err.message}`);
        $notification.post(scriptName, '处理失败', err.message);
        return params;
    }
}

// 清理节点
function cleanNodes(proxies) {
    return proxies.filter(proxy => {
        try {
            // 过滤无效节点
            if (regexConfig.removeNodes.test(proxy.name)) {
                console.log(`删除无效节点: ${proxy.name}`);
                return false;
            }
            
            // 处理节点名称
            const processedName = processNodeName(proxy.name);
            if (processedName) {
                proxy.name = processedName.name;
                return true;
            }
            return false;
        } catch (err) {
            console.log(`节点处理失败: ${proxy.name}, ${err.message}`);
            return false;
        }
    });
}
// 处理节点名称
function processNodeName(name) {
    try {
        let processedName = name;
        
        // 应用地区替换规则
        Object.entries(regexConfig.regionReplace).forEach(([replace, regex]) => {
            processedName = processedName.replace(regex, replace);
        });
        
        // 移除数字序号
        processedName = processedName.replace(regexConfig.number, '');
        
        // 提取地区标识
        const region = Object.entries(regexConfig.regions)
            .find(([_, regex]) => regex.test(processedName))?.[0];
            
        // 提取倍率
        const multiplier = processedName.match(regexConfig.multiplier)?.[0];
        
        // 提取特殊标识
        const specialTag = processedName.match(regexConfig.specialTags)?.[0];
        
        // 组合新名称
        let newName = [];
        if (region) newName.push(region);
        if (specialTag) newName.push(specialTag);
        if (multiplier) newName.push(multiplier);
        
        return {
            name: newName.join(' ') || processedName,
            region,
            multiplier,
            specialTag
        };
    } catch (err) {
        console.log(`节点名称处理失败: ${name}, ${err.message}`);
        return null;
    }
}

// 添加规则配置
function addRules(params) {
    const customRules = [
        // 在此添加自定义规则, 最高优先级
        // 示例:
        //"DOMAIN-SUFFIX,example.com," + proxyName,
    ];

    const rules = [
        ...customRules,
        "RULE-SET,reject,广告拦截",
        "RULE-SET,direct,DIRECT",
        "RULE-SET,cncidr,DIRECT",
        "RULE-SET,private,DIRECT",
        "RULE-SET,lancidr,DIRECT",
        "GEOIP,LAN,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT,no-resolve",
        "RULE-SET,applications,DIRECT",
        "RULE-SET,openai,ChatGPT",
        "RULE-SET,claude,Claude",
        "RULE-SET,spotify,Spotify",
        "RULE-SET,telegramcidr,电报消息,no-resolve",
        "RULE-SET,tld-not-cn," + proxyName,
        "RULE-SET,google," + proxyName,
        "RULE-SET,icloud," + proxyName,
        "RULE-SET,apple," + proxyName,
        "RULE-SET,gfw," + proxyName,
        "RULE-SET,greatfire," + proxyName,
        "RULE-SET,proxy," + proxyName,
        "MATCH,漏网之鱼"
    ];

    const ruleProviders = {
        reject: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
            path: "/.config/clash/ruleset/custom/reject.yaml",
            interval: 86400
        },
        direct: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
            path: "/.config/clash/ruleset/custom/direct.yaml",
            interval: 86400
        },
        proxy: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
            path: "/.config/clash/ruleset/custom/proxy.yaml",
            interval: 86400
        },
        icloud: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt",
            path: "./ruleset/icloud.yaml",
            interval: 86400,
        },
        apple: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
            path: "./ruleset/apple.yaml",
            interval: 86400,
        },
        google: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
            path: "./ruleset/google.yaml",
            interval: 86400,
        },
        private: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
            path: "/.config/clash/ruleset/custom/private.yaml",
            interval: 86400
        },
        gfw: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
            path: "/.config/clash/ruleset/custom/gfw.yaml",
            interval: 86400
        },
        greatfire: {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt",
            path: "/.config/clash/ruleset/custom/greatfire.yaml",
            interval: 86400
        },
        "tld-not-cn": {
            type: "http",
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
            path: "/.config/clash/ruleset/custom/tld-not-cn.yaml",
            interval: 86400
        },
        telegramcidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
            path: "/.config/clash/ruleset/custom/telegramcidr.yaml",
            interval: 86400
        },
        cncidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
            path: "/.config/clash/ruleset/custom/cncidr.yaml",
            interval: 86400
        },
        lancidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
            path: "/.config/clash/ruleset/custom/lancidr.yaml",
            interval: 86400
        },
        applications: {
            type: "http",
            behavior: "classical",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
            path: "/.config/clash/ruleset/custom/applications.yaml",
            interval: 86400
        },
        openai: {
            type: "http",
            behavior: "classical",
            url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml",
            path: "/.config/clash/ruleset/custom/openai.yaml",
            interval: 86400
        },
        claude: {
            type: "http",
            behavior: "classical",
            url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml",
            path: "/.config/clash/ruleset/custom/claude.yaml",
            interval: 86400
        },
        spotify: {
            type: "http",
            behavior: "classical",
            url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml",
            path: "/.config/clash/ruleset/custom/spotify.yaml",
            interval: 86400
        }
    };

    params["rule-providers"] = ruleProviders;
    params.rules = rules;
}

// 添加代理组配置
function addProxyGroups(params) {
    try {
        // 所有代理
        const allProxies = params.proxies.map(p => p.name);
        
        // 自动选择代理组
        const autoProxyGroups = Object.entries(regexConfig.regions).map(([region, regex]) => ({
            name: `${region}-自动选择`,
            type: "url-test",
            url: "http://www.gstatic.com/generate_204",
            interval: 300,
            tolerance: 50,
            "max-failed-times": 3,
            lazy: true,
            proxies: allProxies.filter(name => regex.test(name)),
            hidden: true
        })).filter(group => group.proxies.length > 0);

        // 手动选择代理组
        const manualProxyGroups = Object.entries(regexConfig.regions).map(([region, regex]) => ({
            name: `${region}-手动选择`,
            type: "select",
            proxies: ["DIRECT", ...allProxies.filter(name => regex.test(name))],
            hidden: false
        })).filter(group => group.proxies.length > 1);

        // 生成代理组配置
        const groups = [
            {
                name: proxyName,
                type: "select",
                proxies: ["自动选择", "手动选择", "负载均衡(散列)", "负载均衡(轮询)", "DIRECT"],
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/proxy.svg"
            },
            {
                name: "手动选择",
                type: "select",
                proxies: allProxies,
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/select.svg"
            },
            {
                name: "自动选择",
                type: "url-test",
                url: "http://www.gstatic.com/generate_204",
                interval: 300,
                tolerance: 50,
                "max-failed-times": 3,
                lazy: true,
                proxies: allProxies,
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/auto.svg"
            },
            {
                name: "负载均衡(散列)",
                type: "load-balance",
                strategy: "consistent-hashing",
                url: "http://www.gstatic.com/generate_204",
                interval: 300,
                "max-failed-times": 3,
                lazy: true,
                proxies: allProxies,
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/round-robin.svg"
            },
            {
                name: "负载均衡(轮询)",
                type: "load-balance",
                strategy: "round-robin",
                url: "http://www.gstatic.com/generate_204",
                interval: 300,
                "max-failed-times": 3,
                lazy: true,
                proxies: allProxies,
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/round-robin.svg"
            },
            {
                name: "ChatGPT",
                type: "select",
                proxies: ["美国节点", "日本节点", "手动选择"],
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg"
            },
            {
                name: "Claude",
                type: "select",
                proxies: ["美国节点", "手动选择"],
                icon: "https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev.github.io/main/docs/assets/icons/claude.svg"
            },
            {
                name: "Spotify",
                type: "select",
                proxies: ["DIRECT", proxyName],
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/spotify.svg"
            },
            {
                name: "电报消息",
                type: "select",
                proxies: [proxyName, "手动选择"],
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg"
            },
            {
                name: "广告拦截",
                type: "select",
                proxies: ["REJECT", "DIRECT"],
                icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/reject.svg"
            },
            ...autoProxyGroups,
            ...manualProxyGroups
        ];

        params["proxy-groups"] = groups;
    } catch (err) {
        console.log(`代理组配置失败: ${err.message}`);
        throw err;
    }
}

// 添加DNS配置，防止dns泄露
function addDns(params) {
    try {
        const cnDnsList = [
            "https://223.5.5.5/dns-query",
            "https://1.12.12.12/dns-query",
        ];
        const trustDnsList = [
            'quic://dns.cooluc.com',
            "https://1.0.0.1/dns-query",
            "https://1.1.1.1/dns-query",
        ];

        const dnsOptions = {
            enable: true,
            "prefer-h3": true,
            "default-nameserver": cnDnsList,
            nameserver: trustDnsList,
            "nameserver-policy": {
                "geosite:cn": cnDnsList,
                "geosite:geolocation-!cn": trustDnsList,
            },
            fallback: trustDnsList,
            "fallback-filter": {
                geoip: true,
                "geoip-code": "CN",
                geosite: ["gfw"],
                ipcidr: ["240.0.0.0/4"],
                domain: ["+.google.com", "+.facebook.com", "+.youtube.com"],
            },
        };

        const githubPrefix = "https://fastgh.lainbo.com/";
        const rawGeoxURLs = {
            geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
            geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
            mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
        };

        const accelURLs = Object.fromEntries(
            Object.entries(rawGeoxURLs).map(([key, url]) => [
                key,
                `${githubPrefix}${url}`,
            ])
        );

        const otherOptions = {
            "unified-delay": true,
            "tcp-concurrent": true,
            profile: {
                "store-selected": true,
                "store-fake-ip": true,
            },
            sniffer: {
                enable: true,
                sniff: {
                    TLS: {
                        ports: [443, 8443],
                    },
                    HTTP: {
                        ports: [80, "8080-8880"],
                        "override-destination": true,
                    },
                },
            },
            "geodata-mode": true,
            "geox-url": accelURLs,
        };

        params.dns = { ...params.dns, ...dnsOptions };
        Object.assign(params, otherOptions);
    } catch (err) {
        console.log(`DNS配置失败: ${err.message}`);
        throw err;
    }
}

// 辅助函数
function getProxiesByRegex(params, regex) {
    try {
        const matchedProxies = params.proxies
            .filter(p => regex.test(p.name))
            .map(p => p.name);
        return matchedProxies.length > 0 ? matchedProxies : ["手动选择"];
    } catch (err) {
        console.log(`正则匹配失败: ${err.message}`);
        return ["手动选择"];
    }
}

function getManualProxiesByRegex(params, regex) {
    try {
        const matchedProxies = params.proxies
            .filter(p => regex.test(p.name))
            .map(p => p.name);
        return matchedProxies.length > 0 ? matchedProxies : ["DIRECT", "手动选择", proxyName];
    } catch (err) {
        console.log(`正则匹配失败: ${err.message}`);
        return ["DIRECT", "手动选择", proxyName];
    }
}

// 导出
module.exports = { main };
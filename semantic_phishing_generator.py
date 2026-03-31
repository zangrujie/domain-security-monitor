"""
semantic_phishing_generator.py

统一的域名语义模块：
1. 搜索品牌语义关键词
2. LLM 生成品牌业务关键词
3. 模板化生成疑似钓鱼域名
4. LLM 直接生成疑似钓鱼域名
5. TLD 扩展
6. 对候选域名做语义风险分析（品牌冒用 / 登录验证支付等诱导场景 / 高风险命名模式）

支持命令行模式：
- generate : 只生成候选域名
- analyze  : 只分析给定域名
- both     : 先生成，再分析
"""


import os
import re
import json
import argparse
from typing import List, Dict, Any, Optional

import requests
from dotenv import load_dotenv

import dashscope
from dashscope import Generation


load_dotenv()

DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
SERPER_API_KEY = os.getenv("SERPER_API_KEY")

dashscope.api_key = DASHSCOPE_API_KEY

def safe_json_load(text: str) -> Dict[str, Any]:
    """
    尝试从 LLM 输出中解析 JSON。
    """
    text = (text or "").strip()
    if not text:
        return {}

    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, re.S)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            return {}

    return {}


def normalize_domain(domain: str) -> str:
    """
    规范化域名字符串。
    """
    domain = (domain or "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    return domain


def extract_brand_from_domain(domain: str) -> str:
    """
    从主域名提取品牌词（简单版本）。
    例如：
      coscoshipping.com -> coscoshipping
      paypal.com -> paypal
    """
    domain = normalize_domain(domain)
    if "." not in domain:
        return domain
    return domain.split(".")[0]


def quick_semantic_features(domain: str, brand: str, risky_tlds: List[str]) -> Dict[str, Any]:
    """
    对域名做轻量级本地语义特征提取。
    这一层不调用 LLM，用来辅助后续 prompt 和快速过滤。
    """
    domain = normalize_domain(domain)
    brand = (brand or "").strip().lower()

    if "." in domain:
        sld = ".".join(domain.split(".")[:-1])
        tld = "." + domain.split(".")[-1]
    else:
        sld = domain
        tld = ""

    lure_words = {
        "login", "signin", "sign-in", "verify", "verification", "secure",
        "support", "service", "tracking", "track", "payment", "pay",
        "invoice", "billing", "portal", "account", "auth", "update",
        "customer", "help", "helpdesk", "center", "confirm", "refund"
    }

    tokens = [x for x in re.split(r"[-_.]", sld) if x]
    matched_words = sorted([w for w in lure_words if w in sld])
    has_brand = bool(brand and brand in sld)
    has_lure_word = len(matched_words) > 0
    high_risk_tld = tld in risky_tlds
    brand_plus_lure = has_brand and has_lure_word

    # 粗略命名模式
    pattern_flags = {
        "has_hyphen": "-" in sld,
        "has_number": bool(re.search(r"\d", sld)),
        "multi_token": len(tokens) >= 2,
        "brand_plus_lure": brand_plus_lure,
        "high_risk_tld": high_risk_tld,
    }

    # 粗略攻击意图预估
    rough_intent = "unknown"
    if any(w in matched_words for w in ["login", "signin", "auth", "account"]):
        rough_intent = "login"
    elif any(w in matched_words for w in ["verify", "verification", "confirm", "secure"]):
        rough_intent = "verification"
    elif any(w in matched_words for w in ["payment", "pay", "invoice", "billing", "refund"]):
        rough_intent = "payment"
    elif any(w in matched_words for w in ["support", "service", "help", "helpdesk", "customer", "center"]):
        rough_intent = "support"
    elif any(w in matched_words for w in ["tracking", "track"]):
        rough_intent = "tracking"

    # 一个简单的本地预评分
    local_score = 0
    if has_brand:
        local_score += 35
    if has_lure_word:
        local_score += 20
    if brand_plus_lure:
        local_score += 20
    if high_risk_tld:
        local_score += 10
    if pattern_flags["has_hyphen"]:
        local_score += 5
    if pattern_flags["multi_token"]:
        local_score += 5
    local_score = min(local_score, 100)

    return {
        "domain": domain,
        "brand": brand,
        "sld": sld,
        "tld": tld,
        "tokens": tokens,
        "matched_words": matched_words,
        "has_brand": has_brand,
        "has_lure_word": has_lure_word,
        "high_risk_tld": high_risk_tld,
        "brand_plus_lure": brand_plus_lure,
        "pattern_flags": pattern_flags,
        "rough_intent": rough_intent,
        "local_semantic_score": local_score,
    }


class SemanticPhishingDomainGenerator:
    """
    语义钓鱼域名生成器
    LLM + Web 搜索 + 攻击模式建模
    """

    STOP_WORDS = {
        "login", "home", "page", "official", "website",
        "account", "online", "service"
    }

    def __init__(self, dashscope_api_key: Optional[str]):
        self.dashscope_api_key = dashscope_api_key
        dashscope.api_key = dashscope_api_key

        # 高风险 TLD
        self.risky_tlds = [
            ".xyz", ".top", ".cc", ".vip", ".shop", ".site", ".online", ".net"
        ]

        # 攻击模板
        self.attack_templates = [
            "{brand}-{keyword}",
            "{keyword}-{brand}",
            "{brand}-{keyword}-center",
            "{brand}-{keyword}-portal",
            "secure-{brand}",
            "{brand}-secure",
            "{brand}-{keyword}-verify",
            "{brand}-{keyword}-support",
            "{brand}-{keyword}-login",
            "{brand}-{keyword}-account",
            "{brand}-{keyword}-service",
            "{brand}-{keyword}-tracking",
        ]

        self.default_high_risk_keywords = [
            "login", "signin", "verify", "secure", "support", "tracking",
            "payment", "invoice", "billing", "portal", "account", "auth",
            "customer", "helpdesk", "confirm", "refund"
        ]

    def web_search_keywords_serper(self, domain: str, api_key: Optional[str]) -> List[str]:
        """
        使用 Serper.dev 获取网页标题 + 摘要中的业务关键词。
        """
        if not api_key:
            return []

        brand = extract_brand_from_domain(domain)
        query = f"{brand} account security support login tracking payment official"

        url = "https://google.serper.dev/search"
        headers = {
            "X-API-KEY": api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "q": query,
            "num": 10
        }

        keywords = set()

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            data = response.json()

            organic_results = data.get("organic", [])
            text_data = ""

            for result in organic_results:
                title = result.get("title", "")
                snippet = result.get("snippet", "")
                text_data += f"{title} {snippet} "

            words = re.findall(r"[a-zA-Z]{4,}", text_data.lower())

            for w in words:
                if w == brand:
                    continue
                if w in self.STOP_WORDS:
                    continue
                keywords.add(w)

        except Exception as e:
            print("Serper 搜索失败:", e)

        return list(keywords)[:30]

    def llm_generate_brand_keywords(self, domain: str) -> List[str]:
        """
        使用 LLM 生成品牌最可能涉及的业务关键词。
        """
        if not self.dashscope_api_key:
            return []

        prompt = f"""
品牌域名: {normalize_domain(domain)}

请分析该品牌最可能涉及的业务功能，
生成 12 个用户最可能访问的业务关键词。
要求：
1. 只输出关键词
2. 一行一个
3. 尽量贴近真实攻击者会模仿的业务入口，例如登录、支付、支持、验证、追踪等
"""

        try:
            response = Generation.call(
                model="qwen-plus",
                prompt=prompt,
                temperature=0.6
            )

            if response is None:
                print("LLM 请求失败")
                return []

            if getattr(response, "status_code", 200) != 200:
                print("LLM 调用错误：", getattr(response, "message", "unknown"))
                return []

            try:
                text = response.output["text"]
            except Exception:
                try:
                    text = response.output.text
                except Exception:
                    print("无法解析 LLM 返回内容")
                    return []

            keywords = []
            for line in text.split("\n"):
                line = line.strip().lower()
                line = re.sub(r"^[\-\d\.\s]+", "", line)
                if line and re.match(r"^[a-z][a-z\- ]+$", line):
                    keywords.append(line.replace(" ", "-"))

            return list(dict.fromkeys(keywords))[:20]

        except Exception as e:
            print("LLM 生成品牌关键词失败:", e)
            return []

    def llm_generate_domains(self, domain: str, keywords: List[str]) -> List[str]:
        """
        使用 LLM 直接生成可能的钓鱼域名。
        """
        if not self.dashscope_api_key:
            return []

        domain = normalize_domain(domain)
        brand = extract_brand_from_domain(domain)

        prompt = f"""
目标品牌域名: {domain}
品牌词: {brand}

业务关键词:
{keywords}

请生成 40 个可能用于钓鱼攻击的域名。
要求：
1. 必须体现品牌相关性
2. 尽量模拟真实攻击者风格
3. 优先考虑登录、验证、支付、客服、追踪、账号相关场景
4. 适当使用连字符
5. 看起来像真实业务站点
6. 只输出域名，一行一个，不要解释

示例风格：
{brand}-login.com
secure-{brand}.net
{brand}-tracking.vip
"""

        try:
            response = Generation.call(
                model="qwen-plus",
                prompt=prompt,
                temperature=0.8
            )

            text = response.output.text
            domains = []

            for line in text.split("\n"):
                line = line.strip().lower()
                line = re.sub(r"^[\-\d\.\s]+", "", line)
                line = normalize_domain(line)
                if "." in line and re.match(r"^[a-z0-9][a-z0-9\-\.]+[a-z0-9]$", line):
                    domains.append(line)

            return list(dict.fromkeys(domains))

        except Exception as e:
            print("LLM 生成域名失败:", e)
            return []

    def generate_template_domains(self, domain: str, keywords: List[str]) -> List[str]:
        """
        基于模板生成攻击域名。
        """
        domain = normalize_domain(domain)
        brand = extract_brand_from_domain(domain)

        domains = set()

        for keyword in keywords:
            keyword = keyword.strip().lower().replace(" ", "-")
            if not keyword:
                continue

            for template in self.attack_templates:
                name = template.format(
                    brand=brand,
                    keyword=keyword
                )
                domains.add(f"{name}.com")

        return sorted(domains)

    def expand_tld(self, domains: List[str]) -> List[str]:
        """
        对已有域名做高风险 TLD 扩展。
        """
        expanded = set()

        for domain in domains:
            domain = normalize_domain(domain)
            if "." not in domain:
                continue

            name = ".".join(domain.split(".")[:-1])
            for tld in self.risky_tlds:
                expanded.add(f"{name}{tld}")

        return sorted(expanded)

    def generate(self, target_domain: str, serper_api_key: Optional[str]) -> List[str]:
        """
        主生成流程。
        """
        target_domain = normalize_domain(target_domain)

        print("Step1 Web 搜索关键词")
        web_keywords = self.web_search_keywords_serper(target_domain, serper_api_key)

        print("Step2 LLM 生成品牌关键词")
        llm_keywords = self.llm_generate_brand_keywords(target_domain)

        all_keywords = list(dict.fromkeys(
            self.default_high_risk_keywords + web_keywords + llm_keywords
        ))

        print("关键词:", all_keywords)

        print("Step3 模板攻击生成")
        template_domains = self.generate_template_domains(
            target_domain,
            all_keywords
        )

        print("Step4 LLM 生成域名")
        llm_domains = self.llm_generate_domains(
            target_domain,
            all_keywords
        )

        all_domains = list(dict.fromkeys(template_domains + llm_domains))

        print("Step5 TLD 扩展")
        expanded_domains = self.expand_tld(all_domains)

        result = list(dict.fromkeys(all_domains + expanded_domains))
        return result


class SemanticDomainRiskAnalyzer:
    """
    对域名本身做语义层面的钓鱼风险分析：
    1. 是否包含品牌词
    2. 是否包含诱导性业务词
    3. 是否模拟登录/验证/支付/客服/追踪场景
    4. 是否像真实攻击者会使用的命名方式
    5. 是否属于品牌词 + 业务词 + 高风险 TLD 组合
    """

    def __init__(self, dashscope_api_key: Optional[str], official_whitelist: Optional[Dict[str, Any]] = None):
        self.dashscope_api_key = dashscope_api_key
        dashscope.api_key = dashscope_api_key

        self.official = official_whitelist or {}
        self.brand = (self.official.get("brand", "") or "").lower()
        self.official_domains = set(d.lower() for d in self.official.get("domain", []))

        self.risky_tlds = [
            ".xyz", ".top", ".cc", ".vip", ".shop", ".site", ".online", ".net"
        ]

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        分析单个域名。
        """
        domain = normalize_domain(domain)
        local_features = quick_semantic_features(domain, self.brand, self.risky_tlds)

        # 如果没配 LLM，就直接返回本地分析结果
        if not self.dashscope_api_key:
            score = local_features["local_semantic_score"]
            if score >= 80:
                level = "high"
            elif score >= 50:
                level = "medium"
            else:
                level = "low"

            return {
                "domain": domain,
                "brand_abuse": local_features["has_brand"] and domain not in self.official_domains,
                "semantic_risk_score": score,
                "semantic_risk_level": level,
                "attack_intent": local_features["rough_intent"],
                "matched_keywords": local_features["matched_words"],
                "naming_pattern": "local_rule_only",
                "reason": "未配置 LLM，基于本地语义规则完成初步分析",
                "local_features": local_features
            }

        prompt = f"""
你是网络安全专家，请分析以下域名是否具有钓鱼域名的语义特征。

目标品牌: {self.brand}
官方白名单域名: {sorted(self.official_domains)}
待分析域名: {domain}

本地预提取特征:
{json.dumps(local_features, ensure_ascii=False)}

请重点判断：
1. 是否包含品牌词
2. 是否包含诱导性业务词
3. 是否模拟登录/验证/支付/客服/追踪场景
4. 是否像真实攻击者会使用的命名方式
5. 是否属于“品牌词 + 业务词 + 高风险 TLD”的组合

请严格输出 JSON，不要输出解释文字：
{{
  "domain": "{domain}",
  "brand_abuse": true,
  "semantic_risk_score": 0,
  "semantic_risk_level": "high/medium/low",
  "attack_intent": "login/verification/payment/support/tracking/normal/unknown",
  "matched_keywords": ["..."],
  "naming_pattern": "简短说明命名模式",
  "reason": "简短分析"
}}
"""

        try:
            response = Generation.call(
                model="qwen-plus",
                prompt=prompt,
                temperature=0.2,
                max_tokens=300
            )

            text = response.output.text.strip()
            result = safe_json_load(text)

            if not result:
                raise ValueError("LLM 输出无法解析为 JSON")

            return {
                "domain": domain,
                "brand_abuse": bool(result.get("brand_abuse", False)),
                "semantic_risk_score": int(result.get("semantic_risk_score", local_features["local_semantic_score"]) or 0),
                "semantic_risk_level": str(result.get("semantic_risk_level", "low") or "low"),
                "attack_intent": str(result.get("attack_intent", local_features["rough_intent"]) or "unknown"),
                "matched_keywords": list(result.get("matched_keywords", local_features["matched_words"]) or []),
                "naming_pattern": str(result.get("naming_pattern", "") or ""),
                "reason": str(result.get("reason", "") or ""),
                "local_features": local_features
            }

        except Exception as e:
            return {
                "domain": domain,
                "brand_abuse": local_features["has_brand"] and domain not in self.official_domains,
                "semantic_risk_score": local_features["local_semantic_score"],
                "semantic_risk_level": "medium" if local_features["local_semantic_score"] >= 50 else "low",
                "attack_intent": local_features["rough_intent"],
                "matched_keywords": local_features["matched_words"],
                "naming_pattern": "llm_fallback_local_rule",
                "reason": f"LLM 分析失败，回退到本地规则: {e}",
                "local_features": local_features
            }

    def analyze_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        批量分析域名。
        """
        results = []
        seen = set()

        for domain in domains:
            domain = normalize_domain(domain)
            if not domain or domain in seen:
                continue
            seen.add(domain)
            results.append(self.analyze_domain(domain))

        return results


def build_default_whitelist(target_domain: str) -> Dict[str, Any]:
    """
    如果外部没有传白名单，就构造一个最简默认白名单。
    """
    target_domain = normalize_domain(target_domain)
    brand = extract_brand_from_domain(target_domain).upper()

    return {
        "brand": brand,
        "domain": [target_domain]
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True, help="target domain")
    parser.add_argument("--mode", choices=["generate", "analyze", "both"], default="both")
    parser.add_argument("--limit", type=int, default=30, help="分析时最多分析多少个生成结果")
    args = parser.parse_args()

    target_domain = normalize_domain(args.domain)
    official_whitelist = build_default_whitelist(target_domain)

    generator = SemanticPhishingDomainGenerator(DASHSCOPE_API_KEY)
    analyzer = SemanticDomainRiskAnalyzer(DASHSCOPE_API_KEY, official_whitelist)

    generated_domains: List[str] = []

    if args.mode in ("generate", "both"):
        generated_domains = generator.generate(target_domain, SERPER_API_KEY)

        print("\n生成的域名数量:", len(generated_domains))
        for d in generated_domains[:50]:
            print(d)

    if args.mode in ("analyze", "both"):
        if args.mode == "analyze":
            analyze_targets = [target_domain]
        else:
            analyze_targets = generated_domains[:args.limit]

        results = analyzer.analyze_domains(analyze_targets)

        print("\n语义分析结果:")
        print(json.dumps(results, ensure_ascii=False, indent=2))
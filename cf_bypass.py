#!/usr/bin/env python3
 # -*- coding: utf-8 -*-
"""
Cloudflare 绕过模块

借鉴 newapi-auto-checkin Chrome 扩展的思路：
- 检测 CF 拦截（403 + HTML 验证页面)
- 使用 Playwright 无头浏览器自动过 CF 阴护
- 在同一浏览器会话中完成 CF 绌过 + 磀到签到（不拆分为两步)

两种模式映射:
  Chrome 扩展: service worker fetch → CF 拦截 → 标签页 executeScript
  本项目:      requests 直连 → CF 拦截 → Playwright 同会话内完成签到
"""

import os
import re
import time
from typing import Optional, Tuple


def detect_cloudflare_block(status_code: int, response_text: str) -> Tuple[bool, str]:
    """
    检测 Cloudflare 拦截

    借鉴 background.js:153-156 的检测逻辑:
    - 403 + "Just a moment" / <!DOCTYPE html>
    - 非 JSON 响应包含 <!DOCTYPE 标签
    """
    if status_code == 403:
        if 'Just a moment' in response_text or 'just a moment' in response_text.lower():
            return True, 'Cloudflare JS Challenge (403 + Just a moment)'
        if '<!DOCTYPE html' in response_text.lower() and 'cloudflare' in response_text.lower():
            return True, 'Cloudflare HTML Challenge (403 + Cloudflare page)'

    if status_code == 503:
        if 'cloudflare' in response_text.lower() and ('challenge' in response_text.lower() or 'checking your browser' in response_text.lower()):
            return True, 'Cloudflare Challenge (503)'

    try:
        import json
        json.loads(response_text)
    except (json.JSONDecodeError, ValueError):
        if '<!DOCTYPE' in response_text and ('Just a moment' in response_text or 'challenge-platform' in response_text or 'cf-challenge' in response_text):
            return True, 'Cloudflare Challenge (non-JSON HTML response)'

    return False, ''


def detect_waf_block(status_code: int, response_text: str) -> Tuple[bool, str]:
    """
    检测通用 WAF/JS 挑战拦截（非 Cloudflare 站点也会遇到）

    已知特征:
    - 阿里云盾: var arg1='XXXX' + 混淆脚本（acw_sc__v2 cookie）
    - 其他 JS 挑战: <script>...<html> 结构 + 非 JSON
    """
    if not response_text:
        return False, ''

    # 阿里云盾: 响应为 <html><script>var arg1='...';(function(a,c){... 混淆代码
    if 'var arg1=' in response_text and '<html>' in response_text.lower():
        return True, '阿里云盾 JS 挑战 (acw_sc__v2)'
    if 'acw_sc__v2' in response_text:
        return True, '阿里云盾 JS 挑战 (acw_sc__v2)'

    # 其他 JS 挑战: 非 JSON 且包含混淆脚本特征
    try:
        import json
        json.loads(response_text)
        return False, ''
    except (json.JSONDecodeError, ValueError):
        if '<html>' in response_text.lower() and 'script' in response_text.lower():
            return True, 'WAF JS 挑战 (HTML + script 混淆)'

    return False, ''


class CloudflareBypasser:
    """
    使用 Playwright 无头浏览器绕过 Cloudflare 防护

    核心设计: 在同一个浏览器会话中完成 CF 绕过和签到
    (对应 Chrome 扩展在同一标签页中完成所有操作)
    """

    def __init__(self, base_url: str, session_cookie: str = None, user_id: str = None):
        self.base_url = base_url.rstrip('/')
        self.session_cookie = session_cookie
        self.user_id = user_id
        self._playwright_available = self._check_playwright()
        self.user_info_cache = None  # 浏览器会话内获取的用户信息
        self.history_cache = None    # 浏览器会话内获取的签到历史

    def _check_playwright(self) -> bool:
        try:
            from playwright.sync_api import sync_playwright
            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        return self._playwright_available

    def _solve_cf_challenge(self, page, max_attempts: int = 5, wait_seconds: int = 8) -> bool:
        """
        磻解 CF 验证挑战
        """
        for attempt in range(max_attempts):
            title = page.title()
            current_url = page.url
            print(f'[CF 绕过] 检查 CF 猡证状态 (尝试 {attempt + 1}/{max_attempts}): Title="{title[:50]}"')

            is_cf_challenge = (
                'Just a moment' in title or
                'Checking your browser' in title or
                'Attention Required' in title or
                'cloudflare' in title.lower() and 'challenge' in title.lower()
            )

            if not is_cf_challenge:
                print(f'[CF 绕过] CF 验证已通过: Title="{title}"')
                return True

            print(f'[CF 绕过] CF 验证页面，等待自动解决 ({attempt + 1}/{max_attempts})...')
            try:
                page.wait_for_load_state('networkidle', timeout=30000)
            except Exception:
                pass
            time.sleep(wait_seconds)

        title = page.title()
        is_cf_challenge = (
            'Just a moment' in title or
            'Checking your browser' in title or
            'Attention Required' in title or
            'cloudflare' in title.lower() and 'challenge' in title.lower()
        )
        if not is_cf_challenge:
            print(f'[CF 绕过] CF 验证已通过: Title="{title}"')
            return True

        print('[CF 绕过] CF 验证未能自动解决')
        return False

    def bypass_and_checkin(self, timeout: int = 120) -> Optional[dict]:
        """
        在同一个 Playwright 会话中完成 WAF 绕过 + 签到

        适用于 Cloudflare 和阿里云盾 (acw_sc__v2) 等 JS 挑战:
        1. 启动 Playwright 无头浏览器 (stealth 模式)
        2. 设置 session cookie + New-API-User 请求头
        3. 导航到目标站点，等待 WAF JS 挑战自动解决
        4. WAF 验证通过后，注入 user_id 到 localStorage
        5. 在同一页面内调用 /api/user/sign_in 完成签到
        6. 返回签到结果

        Args:
            timeout: 总超时秒数
        """
        if not self._playwright_available:
            print('[WAF 绕过] Playwright 未安装，无法绕过 WAF 验证')
            return None

        print(f'[WAF 绕过] 使用 Playwright 访问 {self._mask_url(self.base_url)}...')
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = None
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                    ]
                )

                context = browser.new_context(
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080},
                    locale='zh-CN',
                )

                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    window.chrome = { runtime: {} };
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
                """)

                if self.session_cookie:
                    domain = self.base_url.replace('https://', '').replace('http://', '').split('/')[0]
                    context.add_cookies([
                        {'name': 'session', 'value': self.session_cookie, 'domain': domain, 'path': '/'}
                    ])

                page = context.new_page()

                print('[WAF 绕过] 正在加载页面并等待 WAF 验证...')
                page.goto(self.base_url, wait_until='domcontentloaded', timeout=timeout * 1000)

                waf_solved = self._solve_cf_challenge(page, max_attempts=8, wait_seconds=6)

                if not waf_solved:
                    print('[WAF 绕过] WAF 验证未确认，继续尝试签到...')
                else:
                    print('[WAF 绕过] WAF 验证已通过，准备执行签到...')

                # 等待阿里云盾挑战 cookie (acw_sc__v2) 出现且页面稳定（挑战通过后会自动刷新）
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                except Exception:
                    pass
                for _ in range(10):
                    cookies = context.cookies()
                    if any(c['name'] == 'acw_sc__v2' for c in cookies):
                        break
                    page.wait_for_timeout(1000)
                page.wait_for_timeout(2000)  # 等自动刷新完成

                if self.user_id:
                    page.evaluate(f'() => localStorage.setItem("user", JSON.stringify({{"id": {self.user_id}}}))')

                # 浏览器内一次会话完成: 用户信息 + 签到 + 签到历史
                # 必须带 New-API-User 请求头（部分站点要求，否则 401）
                user_id = self.user_id or 0
                browser_data = page.evaluate('''async (uid) => {
                    const headers = {
                        'Content-Type': 'application/json',
                        'New-API-User': String(uid || 0)
                    };
                    const out = { user_info: null, checkin: null, history: null };

                    // 1. 用户信息
                    try {
                        const r = await fetch('/api/user/self', { headers, credentials: 'include' });
                        const t = await r.text();
                        try {
                            const j = JSON.parse(t);
                            out.user_info = { success: j.success === true, data: j.data || null,
                                              message: j.message, httpStatus: r.status };
                        } catch (e) {
                            out.user_info = { error: '非 JSON: ' + t.substring(0, 100), httpStatus: r.status };
                        }
                    } catch (e) { out.user_info = { error: e.message }; }

                    // 2. 签到
                    try {
                        const resp = await fetch('/api/user/sign_in', {
                            method: 'POST',
                            headers: headers,
                            credentials: 'include'
                        });
                        const text = await resp.text();
                        try {
                            const data = JSON.parse(text);
                            const success = data.success === true || data.status === 'success' || data.ret === 1 || data.code === 0;
                            const message = data.message || data.msg || data.data || '签到完成';
                            const msgStr = typeof message === 'string' ? message : JSON.stringify(message);
                            const alreadyKeywords = ['已签到', '已经签到', 'already', '重复签到', '今日已签'];
                            const alreadyCheckedIn = !success && alreadyKeywords.some(k => msgStr.includes(k));
                            out.checkin = {
                                success: success || alreadyCheckedIn,
                                alreadyCheckedIn,
                                message: msgStr,
                                httpStatus: resp.status,
                                data: data
                            };
                        } catch(e) {
                            out.checkin = { error: 'Response is not JSON: ' + text.substring(0, 200), httpStatus: resp.status, success: false };
                        }
                    } catch(e) {
                        out.checkin = { error: e.message, success: false, httpStatus: 0 };
                    }

                    // 3. 签到历史
                    try {
                        const now = new Date();
                        const month = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0');
                        const r = await fetch('/api/user/checkin?month=' + month, { headers, credentials: 'include' });
                        const t = await r.text();
                        try {
                            const j = JSON.parse(t);
                            out.history = { success: j.success === true, data: j.data || null, httpStatus: r.status };
                        } catch (e) {
                            out.history = { error: '非 JSON', httpStatus: r.status };
                        }
                    } catch (e) { out.history = { error: e.message }; }

                    return out;
                }''', user_id)

                # 缓存用户信息与历史，供外部直接使用
                self.user_info_cache = browser_data.get('user_info') or {}
                self.history_cache = browser_data.get('history') or {}
                checkin_result = browser_data.get('checkin') or {}

                print(f'[WAF 绕过] 签到结果: {checkin_result.get("message", checkin_result.get("error", "unknown"))}')
                print(f'[WAF 绕过] 用户信息: {("success" if browser_data.get("user_info", {}).get("success") else "failed")}')
                hist = browser_data.get("history") or {}
                if hist.get("success"):
                    print(f'[WAF 绕过] 签到历史: success')
                elif hist.get("httpStatus") == 200 and not hist.get("error"):
                    pass  # 站点未开放签到历史接口，属于正常情况，静默处理
                else:
                    print(f'[WAF 绕过] 签到历史: failed')

                browser.close()
                return checkin_result

            except Exception as e:
                print(f'[WAF 绕过] Playwright 执行失败: {e}')
                if browser:
                    try:
                        browser.close()
                    except Exception:
                        pass
                return None

    @staticmethod
    def _mask_url(url: str) -> str:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain_parts = parsed.netloc.split('.')
            if len(domain_parts) >= 2:
                masked_domain = f"{domain_parts[0]}.***." + '.'.join(domain_parts[-1:])
            else:
                masked_domain = '***'
            return f"{parsed.scheme}://{masked_domain}"
        except Exception:
            return 'https://***'
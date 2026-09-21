#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NewAPI 自动签到脚本
支持多账号签到，通过 GitHub Actions 定时执行
"""

import os
import sys
import json
import base64
from curl_cffi import requests
from datetime import datetime
from typing import Optional

try:
    from cf_bypass import detect_cloudflare_block, detect_waf_block, CloudflareBypasser
    CF_BYPASS_AVAILABLE = True
except ImportError:
    CF_BYPASS_AVAILABLE = False
    detect_cloudflare_block = None
    detect_waf_block = None
    CloudflareBypasser = None

try:
    from dingtalk_notifier import send_checkin_notification
except ImportError:
    send_checkin_notification = None


class NewAPICheckin:
    """NewAPI 签到类"""

    @staticmethod
    def _mask_url(url: str) -> str:
        """
        脱敏 URL，隐藏域名细节
        例如: https://api.example.com -> https://api.***.**
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain_parts = parsed.netloc.split('.')
            if len(domain_parts) >= 2:
                # 保留第一部分和最后一部分，中间用 *** 代替
                masked_domain = f"{domain_parts[0]}.***." + '.'.join(domain_parts[-1:])
            else:
                masked_domain = '***'
            return f"{parsed.scheme}://{masked_domain}"
        except Exception:
            return 'https://***'

    @staticmethod
    def _mask_user_id(user_id: str) -> str:
        """
        脱敏用户ID
        例如: 1429 -> ****
        """
        return '****'

    def __init__(self, base_url: str, session_cookie: str = None, user_id: str = None,
                 cf_clearance: str = None, username: str = None, password: str = None):
        # 清理 URL：去掉末尾的 / 以及部分 .env 加载器（如 uv）对 # 转义引入的反斜杠
        self.base_url = base_url.strip().rstrip('/').replace('\\', '')
        # session 是 base64（不含反斜杠），清除转义引入的反斜杠
        self.session_cookie = (session_cookie or '').replace('\\', '')
        self.username = (username or '').strip()
        self.password = (password or '').strip()
        self.original_cf_clearance = cf_clearance
        self.cf_bypassed = False
        self.browser_user_info = None  # Playwright 会话内获取的用户信息缓存
        self.browser_history = None    # Playwright 会话内获取的签到历史缓存
        self.login_data = None
        self.logged_in = False
        self.checkin_count = 0

        # 使用 curl_cffi 的浏览器指纹模拟（TLS/JA3），提升 Cloudflare 通过率
        self.session = requests.Session(impersonate='chrome')
        if self.session_cookie:
            self.session.cookies.set('session', self.session_cookie)

        if cf_clearance:
            self.session.cookies.set('cf_clearance', cf_clearance)

        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        })

        if user_id:
            self.user_id = str(user_id)
            self.session.headers.update({'new-api-user': str(self.user_id)})
        elif self.session_cookie:
            self.user_id = self._extract_user_id_from_session(self.session_cookie)
            if self.user_id:
                self.session.headers.update({'new-api-user': str(self.user_id)})
        else:
            self.user_id = None

    def _is_agentrouter(self) -> bool:
        """判断是否为 AgentRouter 平台"""
        return 'agentrouter' in self.base_url.lower()

    def _extract_user_id_from_session(self, session_cookie: str) -> Optional[str]:
        """
        从 Session Cookie 中提取用户ID

        Session Cookie 格式通常是 Base64 编码的数据
        """
        try:
            decoded = base64.b64decode(session_cookie + '==')  # 添加 padding
            decoded_str = decoded.decode('utf-8', errors='ignore')

            import re
            patterns = [
                r'linuxdo[_-](\d+)',  # linuxdo_988
                r'"id"[:\s]+(\d+)',    # "id": 988
                r'user[_-](\d+)',      # user_988
                r'userid[:\s]+(\d+)',  # userid: 988
            ]

            for pattern in patterns:
                match = re.search(pattern, decoded_str, re.IGNORECASE)
                if match:
                    return match.group(1)

        except Exception:
            pass

        return None

    def login(self, verbose: bool = False) -> dict:
        """
        使用用户名/邮箱和密码登录

        Returns:
            dict: {'success': bool, 'message': str, 'checked_in': bool, 'data': dict}
        """
        if not self.username or not self.password:
            return {'success': False, 'message': '未配置用户名或密码', 'checked_in': False}

        login_url = f'{self.base_url}/api/user/login'
        payload = {'username': self.username, 'password': self.password}
        headers = {
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': self.base_url,
            'Referer': f'{self.base_url}/login',
        }

        try:
            resp = self.session.post(login_url, json=payload, headers=headers, timeout=30)
            if verbose:
                print(f'  [调试] 登录 HTTP 状态码: {resp.status_code}')

            # 429 请求过多处理
            if resp.status_code == 429:
                return {
                    'success': False,
                    'message': '请求过于频繁 (HTTP 429: 登录频率限制)，请稍后再试',
                    'checked_in': False,
                    'http_status': 429
                }

            # 检测 WAF 拦截
            is_blocked = False
            reason = ''
            if detect_waf_block:
                is_blocked, reason = detect_waf_block(resp.status_code, resp.text)
            if not is_blocked and detect_cloudflare_block:
                is_blocked, reason = detect_cloudflare_block(resp.status_code, resp.text)
            if is_blocked:
                print(f'[WAF] 登录时检测到 {reason}，尝试浏览器绕过...')
                return self._cf_bypass_login()

            try:
                data = resp.json()
            except json.JSONDecodeError:
                return {'success': False, 'message': f'响应格式非 JSON (HTTP {resp.status_code}): {resp.text[:100]}', 'checked_in': False}

            if resp.status_code == 200 and data.get('success'):
                user_data = data.get('data') or {}
                self.login_data = user_data
                self.logged_in = True

                if 'id' in user_data:
                    self.user_id = str(user_data['id'])
                    self.session.headers.update({'new-api-user': str(self.user_id)})

                new_session = resp.cookies.get('session') or self.session.cookies.get('session')
                if new_session:
                    self.session_cookie = new_session

                checked_in = user_data.get('checked_in', False)
                return {
                    'success': True,
                    'message': data.get('message') or ('签到成功，新增额度已到账' if checked_in else '登录成功！'),
                    'checked_in': checked_in,
                    'data': user_data
                }
            else:
                msg = data.get('message', '未知错误')
                return {'success': False, 'message': f'登录失败: {msg}', 'checked_in': False}

        except requests.exceptions.Timeout:
            return {'success': False, 'message': '登录请求超时', 'checked_in': False}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'message': f'登录网络请求失败: {e}', 'checked_in': False}
        except Exception as e:
            return {'success': False, 'message': f'登录异常: {e}', 'checked_in': False}

    def _cf_bypass_login(self) -> dict:
        """使用 Playwright 绕过 WAF 并执行登录"""
        if not CF_BYPASS_AVAILABLE or not CloudflareBypasser:
            return {'success': False, 'message': '检测到 WAF 拦截，但未安装 Playwright', 'checked_in': False}

        bypasser = CloudflareBypasser(
            self.base_url,
            self.session_cookie,
            self.user_id,
            self.username,
            self.password
        )
        if not bypasser.is_available():
            return {'success': False, 'message': 'Playwright 未正确安装', 'checked_in': False}

        print('[WAF] 开始 Playwright 登录绕过流程...')
        res = bypasser.bypass_and_login()
        if res.get('success'):
            self.cf_bypassed = True
            self.logged_in = True
            if bypasser.session_cookie:
                self.session_cookie = bypasser.session_cookie
                self.session.cookies.set('session', self.session_cookie)
            if bypasser.user_id:
                self.user_id = str(bypasser.user_id)
                self.session.headers.update({'new-api-user': str(self.user_id)})
            self.browser_user_info = bypasser.user_info_cache
            self.browser_history = bypasser.history_cache
        return res

    def get_user_info(self, verbose: bool = False) -> Optional[dict]:
        """
        获取用户信息

        自动设置 new-api-user 请求头
        """
        # 如果配置了用户名和密码且尚未登录且无有效 session，先尝试登录
        if self.username and self.password and not self.logged_in and not self.session_cookie:
            login_res = self.login(verbose=verbose)
            if not login_res['success'] and login_res.get('http_status') != 429:
                return None

        try:
            resp = self.session.get(f'{self.base_url}/api/user/self', timeout=30)

            if verbose:
                print(f'  [调试] HTTP 状态码: {resp.status_code}')
                print(f'  [调试] 响应内容预览: {resp.text[:200]}...')

            # 检查认证失败
            if resp.status_code == 401:
                # 尝试重新登录一次
                if self.username and self.password and not self.logged_in:
                    login_res = self.login(verbose=verbose)
                    if login_res.get('success'):
                        return self.get_user_info(verbose=verbose)
                print(f'[错误] 认证失败 (401): Session 可能已过期')
                if verbose:
                    print(f'  [调试] 完整响应: {resp.text[:500]}')
                return None

            # 尝试解析 JSON
            try:
                data = resp.json()
            except json.JSONDecodeError:
                is_blocked = False
                reason = ''
                if detect_waf_block:
                    is_blocked, reason = detect_waf_block(resp.status_code, resp.text)
                if not is_blocked and detect_cloudflare_block:
                    is_blocked, reason = detect_cloudflare_block(resp.status_code, resp.text)
                if is_blocked:
                    print(f'[WAF] 获取用户信息时检测到 {reason}')
                    return None
                print(f'[错误] 响应格式错误 (HTTP {resp.status_code}): 无法解析 JSON')
                if verbose:
                    print(f'  [调试] 原始响应: {resp.text[:500]}')
                return None

            if resp.status_code == 200:
                if data.get('success'):
                    user_data = data.get('data')
                    if user_data and 'id' in user_data:
                        self.user_id = str(user_data['id'])
                        self.session.headers.update({
                            'new-api-user': str(self.user_id)
                        })
                    return user_data
                else:
                    if verbose:
                        print(f'  [调试] API 返回失败: {data.get("message", "未知错误")}')
            else:
                print(f'[错误] HTTP {resp.status_code}: {data.get("message", "未知错误")}')

            return None

        except requests.exceptions.Timeout:
            print(f'[错误] 请求超时')
            return None
        except requests.exceptions.RequestException as e:
            print(f'[错误] 网络请求失败: {e}')
            return None
        except Exception as e:
            print(f'[错误] 未知错误: {e}')
            if verbose:
                import traceback
                traceback.print_exc()
            return None

    def checkin(self) -> dict:
        """
        执行签到

        如果为 AgentRouter：走邮箱密码登录触发签到流程
        如果是标准 NewAPI：走 requests POST /api/user/sign_in 流程
        """
        if self._is_agentrouter():
            return self._checkin_agentrouter()
        return self._checkin_standard()

    def _checkin_agentrouter(self) -> dict:
        """
        AgentRouter 专属签到流程：
        根据官方规则与 FAQ，该平台只支持邮箱和密码登录，登录动作本身即触发每日签到领 $25 额度。
        平台无 /api/user/sign_in 接口，签到记录可通过 /api/log/self?type=4 获取。
        """
        result = {
            'success': False,
            'message': '',
            'checkin_date': None,
            'quota_awarded': None
        }

        import pytz
        beijing_tz = pytz.timezone('Asia/Shanghai')
        today_str = datetime.now(beijing_tz).strftime('%Y-%m-%d')

        if self.username and self.password:
            if not self.logged_in:
                login_res = self.login()
                if not login_res['success']:
                    # 特殊处理：如果是 429 登录受限，若有 session，尝试从日志确认今日是否已签到
                    if login_res.get('http_status') == 429 and (self.session_cookie or self.session.cookies.get('session')):
                        log_info = self._get_agentrouter_log_status()
                        if log_info and log_info.get('checked_in_today'):
                            result['success'] = True
                            result['message'] = f"今日已完成签到 (登录受限 429，已确认今日记录)"
                            result['checkin_date'] = log_info.get('checkin_date')
                            result['quota_awarded'] = log_info.get('quota_awarded', 12500000)
                            return result
                    result['message'] = login_res['message']
                    return result

            # 登录成功后，从日志获取今日签到详情
            log_info = self._get_agentrouter_log_status()
            if log_info:
                if log_info.get('checked_in_today'):
                    result['success'] = True
                    result['message'] = log_info.get('content') or '每日签到成功，增加额度 ＄25.000000 额度'
                    result['checkin_date'] = log_info.get('checkin_date', today_str)
                    result['quota_awarded'] = log_info.get('quota_awarded', 12500000)
                    return result

            if self.login_data and self.login_data.get('checked_in'):
                result['success'] = True
                result['message'] = '签到成功，新增额度已到账'
                result['checkin_date'] = today_str
                result['quota_awarded'] = 12500000
                return result
            elif self.logged_in:
                result['success'] = True
                result['message'] = '登录成功 (今日已完成签到)'
                result['checkin_date'] = today_str
                return result
            else:
                result['message'] = 'AgentRouter 登录签到失败'
                return result
        else:
            # 仅配置了 session cookie
            if not self.session_cookie:
                result['message'] = 'AgentRouter 必须配置邮箱和密码 (username/password) 登录以完成签到'
                return result

            log_info = self._get_agentrouter_log_status()
            if log_info and log_info.get('checked_in_today'):
                result['success'] = True
                result['message'] = f"今日已签到: {log_info.get('content')}"
                result['checkin_date'] = log_info.get('checkin_date')
                result['quota_awarded'] = log_info.get('quota_awarded', 12500000)
                return result
            else:
                result['message'] = 'AgentRouter 必须通过邮箱和密码登录才算签到，仅有 Session 无法触发签到，请配置 username 与 password'
                return result

    def _get_agentrouter_log_status(self) -> Optional[dict]:
        """从 AgentRouter 的 /api/log/self?type=4 获取签到日志记录"""
        try:
            import pytz
            beijing_tz = pytz.timezone('Asia/Shanghai')
            today_str = datetime.now(beijing_tz).strftime('%Y-%m-%d')

            resp = self.session.get(f'{self.base_url}/api/log/self?type=4', timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('data') and isinstance(data['data'], dict):
                    log_data = data['data']
                    items = log_data.get('items', [])
                    total = log_data.get('total', 0)
                    self.checkin_count = total
                    if items:
                        latest = items[0]
                        created_at = latest.get('created_at', 0)
                        log_date = datetime.fromtimestamp(created_at, beijing_tz).strftime('%Y-%m-%d')
                        content = latest.get('content', '')
                        quota_awarded = 12500000  # $25 * 500,000 = 12,500,000 tokens
                        return {
                            'checked_in_today': (log_date == today_str),
                            'checkin_date': log_date,
                            'content': content,
                            'quota_awarded': quota_awarded,
                            'total': total
                        }
        except Exception:
            pass
        return None

    def _checkin_standard(self) -> dict:
        """标准 NewAPI 签到流程"""
        result = {
            'success': False,
            'message': '',
            'checkin_date': None,
            'quota_awarded': None
        }

        try:
            resp = self.session.post(f'{self.base_url}/api/user/sign_in', timeout=30)

            if resp.status_code == 401:
                result['message'] = '认证失败: Session 可能已过期，请重新获取'
                return result

            try:
                data = resp.json()
            except json.JSONDecodeError:
                # 检测 WAF 拦截（Cloudflare / 阿里云盾），走浏览器绕过
                is_blocked = False
                reason = ''
                if detect_waf_block:
                    is_blocked, reason = detect_waf_block(resp.status_code, resp.text)
                if not is_blocked and detect_cloudflare_block:
                    is_blocked, reason = detect_cloudflare_block(resp.status_code, resp.text)
                if is_blocked:
                    print(f'[WAF] 检测到拦截: {reason}')
                    return self._cf_bypass_checkin()
                content_preview = resp.text[:200] if resp.text else '(空响应)'
                result['message'] = f'响应格式错误 (HTTP {resp.status_code}): {content_preview}'
                return result

            if detect_cloudflare_block and resp.status_code in (403, 503):
                is_blocked, reason = detect_cloudflare_block(resp.status_code, json.dumps(data))
                if is_blocked:
                    print(f'[WAF] 检测到 Cloudflare 拦截: {reason}')
                    return self._cf_bypass_checkin()

            if resp.status_code == 200:
                if data.get('success'):
                    result['success'] = True
                    result['message'] = data.get('message', '签到成功')

                    checkin_data = data.get('data', {})
                    result['checkin_date'] = checkin_data.get('checkin_date')
                    result['quota_awarded'] = checkin_data.get('quota_awarded')
                else:
                    result['message'] = data.get('message', '签到失败')
            else:
                result['message'] = f'HTTP {resp.status_code}: {data.get("message", "未知错误")}'

        except requests.exceptions.Timeout:
            result['message'] = '请求超时'
        except requests.exceptions.RequestException as e:
            result['message'] = f'网络请求失败: {e}'
        except Exception as e:
            result['message'] = f'未知错误: {e}'

        return result

    def _cf_bypass_checkin(self) -> dict:
        """
        CF 绕过签到流程

        在同一个 Playwright 会话中完成 CF 绕过 + 签到，
        不拆分 cookie 提取和 requests 重试（因为 cf_clearance 绑定浏览器指纹）
        """
        result = {
            'success': False,
            'message': '',
            'checkin_date': None,
            'quota_awarded': None
        }

        if not CF_BYPASS_AVAILABLE or not CloudflareBypasser:
            result['message'] = 'Cloudflare 拦截: 需安装 Playwright 才能自动绕过 (pip install playwright && playwright install chromium)'
            return result

        bypasser = CloudflareBypasser(
            self.base_url,
            self.session_cookie,
            self.user_id,
            self.username,
            self.password
        )

        if not bypasser.is_available():
            result['message'] = 'Cloudflare 拦截: Playwright 未正确安装'
            return result

        print('[WAF] 开始 Playwright 绕过流程...')
        browser_result = bypasser.bypass_and_checkin()

        if not browser_result:
            result['message'] = 'WAF 绕过失败: 无法通过验证'
            return result

        self.cf_bypassed = True

        if browser_result.get('error'):
            result['message'] = f'WAF 绕过后签到失败: {browser_result["error"]}'
            return result

        # 同一浏览器会话内顺带获取用户信息和签到历史，避免再次被 WAF 拦截
        self.browser_user_info = bypasser.user_info_cache
        self.browser_history = bypasser.history_cache

        if browser_result.get('alreadyCheckedIn'):
            result['success'] = True
            result['message'] = browser_result.get('message', '今日已签到 (WAF绕过)')
        elif browser_result.get('success'):
            result['success'] = True
            result['message'] = browser_result.get('message', '签到成功 (WAF绕过)')
            data = browser_result.get('data', {})
            if isinstance(data, dict):
                checkin_data = data.get('data', data)
                result['checkin_date'] = checkin_data.get('checkin_date')
                result['quota_awarded'] = checkin_data.get('quota_awarded')
        else:
            result['message'] = browser_result.get('message', 'WAF 绕过后签到失败')

        return result

    def get_checkin_history(self, month: str = None, verbose: bool = False) -> Optional[dict]:
        """
        获取签到历史

        Args:
            month: 月份，格式 YYYY-MM，默认当前月
        """
        if self._is_agentrouter():
            log_info = self._get_agentrouter_log_status()
            total = self.checkin_count or (log_info.get('total', 0) if log_info else 0)
            if total > 0 or log_info:
                checked_in_today = log_info.get('checked_in_today', False) if log_info else False
                return {
                    'stats': {
                        'checkin_count': total,
                        'total_quota': total * 12500000,
                        'checked_in_today': checked_in_today
                    }
                }
            return None

        if month is None:
            month = datetime.now().strftime('%Y-%m')

        try:
            resp = self.session.get(
                f'{self.base_url}/api/user/checkin',
                params={'month': month},
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    return data.get('data')
                # 部分站点未开放签到历史接口（success=false），静默跳过
            return None
        except Exception as e:
            # 历史接口属于增值统计，失败不阻塞主流程
            if verbose:
                print(f'[错误] 获取签到历史失败: {e}')
            return None


def parse_accounts(accounts_str: str) -> list:
    """
    解析账号配置

    支持格式:
    1. 单账号: BASE_URL#SESSION_COOKIE 或 BASE_URL#USERNAME#PASSWORD
    2. 多账号: BASE_URL1#SESSION1,BASE_URL2#SESSION2
    3. JSON格式:
       [{"url": "...", "session": "..."}] 或
       [{"url": "...", "username": "...", "password": "..."}]
    """
    accounts = []

    if not accounts_str:
        return accounts

    # 尝试 JSON 格式
    try:
        data = json.loads(accounts_str)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'url' in item:
                    session = item.get('session', '')
                    username = item.get('username') or item.get('email') or ''
                    password = item.get('password', '')

                    # 既无 session 也无 username+password 则跳过
                    if not session and not (username and password):
                        continue

                    account = {
                        'url': item['url'],
                        'session': session,
                        'username': username,
                        'password': password,
                        'name': item.get('name', '')
                    }
                    if 'user_id' in item:
                        account['user_id'] = item['user_id']
                    if 'cf_clearance' in item:
                        account['cf_clearance'] = item['cf_clearance']
                    accounts.append(account)
            return accounts
    except json.JSONDecodeError:
        pass

    # 简单格式: URL#SESSION 或 URL#USERNAME#PASSWORD
    for part in accounts_str.split(','):
        part = part.strip()
        if '#' in part:
            pieces = [p.strip() for p in part.split('#')]
            if len(pieces) == 2:
                accounts.append({
                    'url': pieces[0],
                    'session': pieces[1],
                    'username': '',
                    'password': '',
                    'name': ''
                })
            elif len(pieces) >= 3:
                url, p2, p3 = pieces[0], pieces[1], pieces[2]
                if '@' in p2 or not p3.isdigit():
                    accounts.append({
                        'url': url,
                        'session': '',
                        'username': p2,
                        'password': p3,
                        'name': ''
                    })
                else:
                    accounts.append({
                        'url': url,
                        'session': p2,
                        'user_id': p3,
                        'username': '',
                        'password': '',
                        'name': ''
                    })

    return accounts


def load_config_from_cloud(config_url: str, config_auth: str = None) -> Optional[str]:
    """
    从云端（WebDAV）加载配置

    支持:
    - 坚果云 WebDAV
    - 群晖 NAS WebDAV
    - NextCloud WebDAV
    - 任何支持 WebDAV/直接链接的云存储

    Args:
        config_url: 配置文件 URL (WebDAV 或直接下载链接)
        config_auth: 认证信息，格式:
            - Basic Auth: "username:password"
            - Token Auth: "token:your_token"
    """
    try:
        headers = {}

        if config_auth:
            if config_auth.startswith('token:'):
                headers['Authorization'] = 'Bearer ' + config_auth[6:]
            elif ':' in config_auth:
                import base64 as b64mod
                credentials = b64mod.b64encode(config_auth.encode('utf-8')).decode('utf-8')
                headers['Authorization'] = 'Basic ' + credentials

        print(f'[云端] 正在从云端加载配置: {NewAPICheckin._mask_url(config_url)}')

        resp = requests.get(config_url, headers=headers, timeout=30)

        if resp.status_code == 401:
            print('[云端] 认证失败: 请检查 CONFIG_AUTH 配置')
            return None
        elif resp.status_code == 404:
            print('[云端] 配置文件不存在: 请先通过配置生成器保存到云端')
            return None
        elif resp.status_code != 200:
            print(f'[云端] 加载失败: HTTP {resp.status_code}')
            return None

        data = resp.json()

        if isinstance(data, list):
            accounts_str = json.dumps(data)
            print(f'[云端] 成功加载 {len(data)} 个账号配置')
            return accounts_str
        elif isinstance(data, dict) and 'accounts' in data:
            accounts = data['accounts']
            accounts_str = json.dumps(accounts)
            print(f'[云端] 成功加载 {len(accounts)} 个账号配置')

            if data.get('dingtalk'):
                dt = data['dingtalk']
                if dt.get('webhook') and not os.environ.get('DINGTALK_WEBHOOK'):
                    os.environ['DINGTALK_WEBHOOK'] = dt['webhook']
                if dt.get('secret') and not os.environ.get('DINGTALK_SECRET'):
                    os.environ['DINGTALK_SECRET'] = dt['secret']
                if dt.get('webhook'):
                    print('[云端] 已从云端加载钉钉通知配置')

            return accounts_str
        else:
            print('[云端] 配置格式错误: 无法解析账号列表')
            return None

    except json.JSONDecodeError:
        print('[云端] 配置文件不是有效的 JSON 格式')
        return None
    except requests.exceptions.Timeout:
        print('[云端] 请求超时')
        return None
    except requests.exceptions.RequestException as e:
        print(f'[云端] 网络请求失败: {e}')
        return None
    except Exception as e:
        print(f'[云端] 加载失败: {e}')
        return None


def main():
    """主函数"""
    import pytz
    beijing_tz = pytz.timezone('Asia/Shanghai')
    execution_time = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")
    print('=' * 50)
    print('NewAPI 自动签到')
    print(f'执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('=' * 50)

    # 尝试加载本地 .env 文件
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

    config_url = os.environ.get('CONFIG_URL', '')
    config_auth = os.environ.get('CONFIG_AUTH', '')

    accounts_str = ''

    if config_url:
        accounts_str = load_config_from_cloud(config_url, config_auth) or ''

    if not accounts_str:
        accounts_str = os.environ.get('NEWAPI_ACCOUNTS', '')

    if not accounts_str:
        print('[错误] 未配置账号信息')
        print('请设置 CONFIG_URL（云端配置）或 NEWAPI_ACCOUNTS（本地配置）环境变量')
        sys.exit(1)

    accounts = parse_accounts(accounts_str)

    if not accounts:
        print('[错误] 账号配置解析失败')
        sys.exit(1)

    print(f'共 {len(accounts)} 个账号待签到\n')

    success_count = 0
    fail_count = 0
    checkin_results = []

    for i, account in enumerate(accounts, 1):
        url = account['url']
        session_cookie = account.get('session', '')
        user_id = account.get('user_id')  # 获取用户ID（如果提供）
        cf_clearance = account.get('cf_clearance')  # 获取 CF clearance（如果提供）
        username = account.get('username') or account.get('email') or ''
        password = account.get('password', '')
        name = account.get('name') or f'账号{i}'

        print(f'[{i}/{len(accounts)}] {name}')
        print(f'  站点: {NewAPICheckin._mask_url(url)}')
        if user_id:
            print(f'  用户ID: {NewAPICheckin._mask_user_id(user_id)}')
        elif username:
            masked_acc = (username[:3] + '***' + username[username.find('@'):]) if '@' in username else (username[:3] + '***')
            print(f'  账号: {masked_acc}')

        client = NewAPICheckin(
            base_url=url,
            session_cookie=session_cookie,
            user_id=user_id,
            cf_clearance=cf_clearance,
            username=username,
            password=password
        )

        # 尝试直连获取用户信息（非 WAF 站点直接成功）
        user_info = client.get_user_info()

        # 执行签到（直连被 WAF 拦截时，浏览器会话会顺带获取用户信息）
        result = client.checkin()
        checkin_count = 0  # 默认值，避免历史接口失败时未定义

        # 用户信息：直连结果优先，否则用浏览器会话内获取的结果
        user_display = ''
        user_quota = None
        if user_info and isinstance(user_info, dict):
            user_display = user_info.get('display_name') or user_info.get('username', '')
            user_quota = user_info.get('quota')
        elif client.browser_user_info and client.browser_user_info.get('success'):
            b_data = client.browser_user_info.get('data')
            if isinstance(b_data, dict):
                user_display = b_data.get('display_name') or b_data.get('username', '')
                user_quota = b_data.get('quota')

        if user_display:
            masked_username = user_display[:3] + '***' if len(user_display) > 3 else '***'
            print(f'  用户: {masked_username}')
            if user_quota is not None:
                quota_usd = user_quota / 500000.0
                print(f'  余额: ${quota_usd:.2f} ({user_quota:,} tokens)')
        else:
            print('  用户: 获取失败（可能 session 已过期或受限）')

        if result['success']:
            success_count += 1
            print(f'  结果: ✅ {result["message"]}')

            # 显示签到日期
            if result['checkin_date']:
                print(f'  日期: {result["checkin_date"]}')

            # 显示获得的额度（格式化显示）
            if result['quota_awarded']:
                quota = result['quota_awarded']
                # 格式化额度显示
                if quota >= 1000000:
                    quota_str = f'{quota / 1000000:.2f}M'
                elif quota >= 1000:
                    quota_str = f'{quota / 1000:.2f}K'
                else:
                    quota_str = str(quota)
                print(f'  奖励: +{quota_str} 额度 ({quota:,} tokens)')

            # 获取本月签到统计
            history = client.get_checkin_history()
            if not history and client.browser_history:
                b_hist = client.browser_history
                if b_hist.get('success'):
                    history = b_hist.get('data')
            if history and history.get('stats'):
                stats = history['stats']
                checkin_count = stats.get('checkin_count', 0)
                total_quota = stats.get('total_quota', 0)
                if total_quota >= 1000000:
                    total_str = f'{total_quota / 1000000:.2f}M'
                elif total_quota >= 1000:
                    total_str = f'{total_quota / 1000:.2f}K'
                else:
                    total_str = str(total_quota)
                print(f'  统计: 本月已签 {checkin_count} 天，累计 {total_str} 额度')

            # 收集结果用于钉钉通知
            account_result = {
                'name': name,
                'success': True,
                'message': result['message'],
                'quota_awarded': result.get('quota_awarded'),
                'checkin_count': checkin_count
            }
            checkin_results.append(account_result)
        else:
            fail_count += 1
            print(f'  结果: ❌ {result["message"]}')

            # 收集结果用于钉钉通知
            message = result.get('message', '')
            account_result = {
                'name': name,
                'success': False,
                'message': message,
                'session_expired': 'session' in message.lower() or '认证' in message
            }
            checkin_results.append(account_result)

        print()

    # 汇总
    print('=' * 50)
    print(f'签到完成: 成功 {success_count}, 失败 {fail_count}')
    print('=' * 50)
    
    # 发送钉钉通知
    if send_checkin_notification:
        print('正在发送钉钉通知...')
        send_checkin_notification(checkin_results, execution_time)
    elif os.environ.get('DINGTALK_WEBHOOK'):
        print('[警告] 已配置 DINGTALK_WEBHOOK 但无法导入通知模块')

    # 如果全部失败则返回错误码
    if fail_count == len(accounts):
        sys.exit(1)


if __name__ == '__main__':
    main()

# === DINGTALK NOTIFICATION PATCH ===
# This section was added to send DingTalk notifications

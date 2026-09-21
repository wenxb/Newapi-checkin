#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NewAPI 签到测试脚本
用于快速测试单个站点的签到功能，支持 Session 模式与邮箱/密码模式（AgentRouter 等）
"""

import sys
from checkin import NewAPICheckin


def test_checkin(base_url: str, session_cookie: str = None, user_id: str = None,
                 username: str = None, password: str = None, verbose: bool = False):
    """测试签到功能"""
    print('=' * 50)
    print('NewAPI 签到测试')
    print('=' * 50)
    print(f'站点: {base_url}')
    if session_cookie:
        print(f'认证模式: Session Cookie ({len(session_cookie)} 字符)')
        if verbose:
            print(f'Session 开头: {session_cookie[:50]}...')
    elif username and password:
        masked_u = (username[:3] + '***' + username[username.find('@'):]) if '@' in username else (username[:3] + '***')
        print(f'认证模式: 邮箱/用户名密码 (账号: {masked_u})')
    if user_id:
        print(f'用户ID: {user_id} (手动指定)')
    print()

    # 创建客户端
    client = NewAPICheckin(
        base_url=base_url,
        session_cookie=session_cookie,
        user_id=user_id,
        username=username,
        password=password
    )

    # 显示提取的用户ID
    if client.user_id:
        print(f'✅ 用户ID: {client.user_id}')
    else:
        print('ℹ️  尚未获取用户ID，将尝试从 API 获取')
    print()

    # 测试获取用户信息
    print('[1/3] 测试获取用户信息...')
    user_info = client.get_user_info(verbose=verbose)
    if user_info:
        print(f'✅ 成功')
        user_display = user_info.get('display_name') or user_info.get('username')
        print(f'  用户: {user_display}')
        print(f'  用户ID: {user_info.get("id")}')
        if 'quota' in user_info:
            q = user_info['quota']
            print(f'  当前额度: ${q / 500000.0:.2f} ({q:,} tokens)')
    else:
        print('❌ 失败 - 无法获取用户信息')
        print('\n💡 问题排查：')
        print('  1. 检查 Session Cookie 或用户名/密码是否正确')
        print('  2. 如提示 429 请等待几分钟后重试')
        print('  3. 使用 --verbose 参数查看详细错误信息')
        return False

    # 测试签到
    print('\n[2/3] 测试签到...')
    result = client.checkin()
    if result['success']:
        print(f'✅ {result["message"]}')
        if result['checkin_date']:
            print(f'  签到日期: {result["checkin_date"]}')
        if result['quota_awarded']:
            quota = result['quota_awarded']
            if quota >= 1000000:
                quota_str = f'{quota / 1000000:.2f}M'
            elif quota >= 1000:
                quota_str = f'{quota / 1000:.2f}K'
            else:
                quota_str = str(quota)
            print(f'  获得额度: +{quota_str} ({quota:,} tokens)')
    else:
        print(f'❌ {result["message"]}')
        return False

    # 测试获取签到历史
    print('\n[3/3] 测试获取签到历史...')
    history = client.get_checkin_history(verbose=verbose)
    if history:
        print('✅ 成功')
        if history.get('stats'):
            stats = history['stats']
            print(f'  本月签到: {stats.get("checkin_count", 0)} 天')
            total = stats.get('total_quota', 0)
            if total >= 1000000:
                total_str = f'{total / 1000000:.2f}M'
            elif total >= 1000:
                total_str = f'{total / 1000:.2f}K'
            else:
                total_str = str(total)
            print(f'  累计额度: {total_str} ({total:,} tokens)')
            print(f'  今日已签: {"是" if stats.get("checked_in_today") else "否"}')
    else:
        print('⚠️  获取失败（不影响签到）')

    print('\n' + '=' * 50)
    print('测试完成！所有功能正常 ✅')
    print('=' * 50)
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('使用方法：')
        print('  # 1. 邮箱/密码方式（AgentRouter 推荐）：')
        print('  python test_checkin.py <BASE_URL> --username <USERNAME> --password <PASSWORD> [选项]')
        print('  python test_checkin.py <BASE_URL> <USERNAME> <PASSWORD> [选项]')
        print('')
        print('  # 2. Session Cookie 方式（AnyRouter 等）：')
        print('  python test_checkin.py <BASE_URL> <SESSION_COOKIE> [选项]')
        print('')
        print('参数说明：')
        print('  BASE_URL       - 站点地址，如 https://agentrouter.org 或 https://anyrouter.top')
        print('  --username     - 邮箱或用户名')
        print('  --password     - 登录密码')
        print('  --user-id      - 指定用户ID（可选）')
        print('  --verbose, -v  - 显示详细调试信息')
        print('')
        print('示例：')
        print('  python test_checkin.py https://agentrouter.org --username wjhzlq999@163.com --password 2yueliang')
        print('  python test_checkin.py https://anyrouter.top MTc2NzQxMzYzM... --user-id 123')
        sys.exit(1)

    base_url = sys.argv[1]
    session_cookie = None
    username = None
    password = None
    user_id = None
    verbose = False

    args = sys.argv[2:]
    idx = 0
    positional = []

    while idx < len(args):
        arg = args[idx]
        if arg in ['--verbose', '-v']:
            verbose = True
            idx += 1
        elif arg == '--user-id' and idx + 1 < len(args):
            user_id = args[idx + 1]
            idx += 2
        elif arg == '--username' and idx + 1 < len(args):
            username = args[idx + 1]
            idx += 2
        elif arg == '--password' and idx + 1 < len(args):
            password = args[idx + 1]
            idx += 2
        else:
            positional.append(arg)
            idx += 1

    if not username and not password:
        if len(positional) >= 2 and ('@' in positional[0] or not positional[1].isdigit()):
            username = positional[0]
            password = positional[1]
        elif len(positional) >= 1:
            session_cookie = positional[0]

    if not session_cookie and not (username and password):
        print('❌ 错误：请提供 Session Cookie 或提供 --username 与 --password')
        sys.exit(1)

    if verbose:
        print('[调试模式已启用]\n')

    success = test_checkin(
        base_url=base_url,
        session_cookie=session_cookie,
        user_id=user_id,
        username=username,
        password=password,
        verbose=verbose
    )
    sys.exit(0 if success else 1)

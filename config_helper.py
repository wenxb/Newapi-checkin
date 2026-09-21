#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NewAPI 配置助手
交互式生成 NEWAPI_ACCOUNTS 环境变量配置
"""

import json
import sys


def print_banner():
    """打印欢迎信息"""
    print('=' * 60)
    print('NewAPI 自动签到 - 配置助手')
    print('=' * 60)
    print('这个工具将帮助你生成 NEWAPI_ACCOUNTS 配置')
    print('支持多个站点、多个账号的配置\n')


def get_input(prompt: str, default: str = None) -> str:
    """获取用户输入"""
    if default:
        prompt = f'{prompt} [{default}]'
    value = input(f'{prompt}: ').strip()
    return value if value else default


def get_yes_no(prompt: str, default: bool = True) -> bool:
    """获取是/否输入"""
    default_str = 'Y/n' if default else 'y/N'
    value = input(f'{prompt} ({default_str}): ').strip().lower()
    if not value:
        return default
    return value in ['y', 'yes', '是']


def test_account(url: str, session: str = None, username: str = None, password: str = None) -> bool:
    """测试账号配置是否有效"""
    try:
        from checkin import NewAPICheckin
        client = NewAPICheckin(url, session_cookie=session, username=username, password=password)
        user_info = client.get_user_info()
        if user_info:
            name = user_info.get("display_name") or user_info.get("username")
            print(f'  ✅ 测试成功！用户: {name}')
            return True
        else:
            print('  ❌ 测试失败：无法获取用户信息（凭据可能无效或登录受限）')
            return False
    except Exception as e:
        print(f'  ❌ 测试失败: {e}')
        return False


def collect_accounts():
    """收集账号信息"""
    accounts = []
    account_num = 1

    while True:
        print(f'\n--- 配置第 {account_num} 个账号 ---')

        # 站点 URL
        while True:
            url = get_input('站点 URL（如 https://agentrouter.org 或 https://anyrouter.top）')
            if not url:
                print('❌ URL 不能为空')
                continue
            if not url.startswith('http'):
                url = 'https://' + url
            break

        # 备注名称（可选）
        name = get_input('备注名称（可选，便于识别）', f'站点{account_num}')

        # 选择认证方式
        is_agent = 'agentrouter' in url.lower()
        default_choice = '2' if is_agent else '1'
        print('\n选择认证方式：')
        print('1. Session Cookie（传统 NewAPI 站点）')
        print('2. 邮箱/用户名 + 密码（AgentRouter 必须，或无需定期更新 Cookie）')
        auth_choice = get_input('请选择认证方式 (1/2)', default_choice)

        session = ''
        username = ''
        password = ''
        user_id = ''

        if auth_choice == '2':
            # 邮箱/用户名 + 密码
            while True:
                username = get_input('登录邮箱或用户名')
                if not username:
                    print('❌ 账号不能为空')
                    continue
                break
            while True:
                password = get_input('登录密码')
                if not password:
                    print('❌ 密码不能为空')
                    continue
                break

            # 是否测试
            if get_yes_no('是否测试此账号配置', True):
                print('正在测试登录...')
                test_account(url, username=username, password=password)

            account_data = {
                'url': url,
                'username': username,
                'password': password,
                'name': name
            }
        else:
            # Session Cookie
            while True:
                session = get_input('Session Cookie')
                if not session:
                    print('❌ Session 不能为空')
                    continue
                break

            # 用户ID（选填/推荐）
            user_id = get_input('用户ID（可选，如 user_123 的ID是 123）', '').strip()

            # 是否测试
            if get_yes_no('是否测试此账号配置', True):
                print('正在测试...')
                test_account(url, session=session)

            account_data = {
                'url': url,
                'session': session,
                'name': name
            }
            if user_id:
                account_data['user_id'] = user_id

        accounts.append(account_data)

        print(f'✅ 第 {account_num} 个账号添加成功')

        # 是否继续添加

        if not get_yes_no('\n是否继续添加账号', False):
            break

        account_num += 1

    return accounts


def generate_config(accounts: list) -> dict:
    """生成配置字符串"""
    # JSON 格式（推荐）
    json_config = json.dumps(accounts, ensure_ascii=False, indent=2)

    # 简单格式
    simple_config = ','.join([f"{acc['url']}#{acc['session']}" for acc in accounts])

    return {
        'json': json_config,
        'simple': simple_config
    }


def save_to_file(content: str, filename: str):
    """保存到文件"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f'✅ 已保存到文件: {filename}')
        return True
    except Exception as e:
        print(f'❌ 保存失败: {e}')
        return False


def main():
    """主函数"""
    print_banner()

    # 收集账号信息
    accounts = collect_accounts()

    if not accounts:
        print('\n❌ 没有配置任何账号')
        sys.exit(1)

    # 生成配置
    print('\n' + '=' * 60)
    print('配置生成成功！')
    print('=' * 60)

    configs = generate_config(accounts)

    # 显示 JSON 格式（推荐）
    print('\n【方式 1】JSON 格式（推荐，支持备注）：')
    print('-' * 60)
    print(configs['json'])
    print('-' * 60)

    # 显示简单格式
    print('\n【方式 2】简单格式（不支持备注）：')
    print('-' * 60)
    print(configs['simple'])
    print('-' * 60)

    # 使用说明
    print('\n📋 使用方法：')
    print('\n1. 本地运行：')
    print('   - Linux/macOS: export NEWAPI_ACCOUNTS=\'<上面的配置>\'')
    print('   - Windows CMD: set NEWAPI_ACCOUNTS=<上面的配置>')
    print('   - Windows PowerShell: $env:NEWAPI_ACCOUNTS=\'<上面的配置>\'')
    print('\n2. GitHub Actions：')
    print('   - 进入仓库 Settings → Secrets and variables → Actions')
    print('   - 新建 Secret，名称: NEWAPI_ACCOUNTS')
    print('   - 值: 复制上面的 JSON 格式配置')

    # 保存选项
    if get_yes_no('\n是否保存配置到文件', True):
        print('\n选择保存格式：')
        print('1. JSON 格式（推荐）')
        print('2. 简单格式')
        print('3. 两种都保存')

        choice = get_input('请选择 (1/2/3)', '1')

        if choice in ['1', '3']:
            save_to_file(configs['json'], 'newapi_accounts.json')

        if choice in ['2', '3']:
            save_to_file(configs['simple'], 'newapi_accounts.txt')

    print('\n' + '=' * 60)
    print('配置完成！')
    print('=' * 60)
    print('\n💡 提示：')
    print('- JSON 文件和 TXT 文件已添加到 .gitignore，不会被提交')
    print('- 请妥善保管 Session Cookie，不要泄露给他人')
    print('- Session 通常 7-30 天过期，请定期更新')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n❌ 用户取消操作')
        sys.exit(1)
    except Exception as e:
        print(f'\n\n❌ 发生错误: {e}')
        sys.exit(1)

# app.py - 雪球监控后台服务
import json
import logging
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

import jwt
import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ========== 配置部分 ==========
app = Flask(__name__)
CORS(app)  # 允许跨域请求
app.config['SECRET_KEY'] = 'your-secret-key-change-this'  # 生产环境请使用强密钥
app.config['DATABASE'] = 'D:\\sqlite3\\monitor.db'
app.config['JWT_EXPIRATION_HOURS'] = 24 * 7  # JWT有效期7天
app.config['INTERVAL'] = 15  # 轮询间隔（秒）

# 关注类型常量
FOLLOW_TYPE_USER = 'user'  # 关注用户
FOLLOW_TYPE_CUBE = 'cube'  # 关注组合
FOLLOW_TYPE_OTHER = 'other'  # 其他平台（预留）

XQ_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json',
    'Cookie': "u=9696783696;xq_a_token=7cf37d4239b032b7bdfb7011f5ca303e4110c8c7"
}


# ========== 数据库初始化 ==========
def get_db():
    """获取数据库连接"""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    """初始化数据库表"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 用户表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')

        # 统一的关注表（整合用户和组合）
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                follow_type TEXT NOT NULL,  -- 'user'/'cube'/'other'
                platform TEXT DEFAULT 'xueqiu',  -- 平台标识
                target_id TEXT NOT NULL,  -- 目标ID（雪球UID/组合symbol等）
                target_name TEXT NOT NULL,  -- 目标名称
                extra_info TEXT,  -- 额外信息（JSON格式）
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, follow_type, platform, target_id)
            )
        ''')

        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_user ON follows (user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_type ON follows (follow_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_platform ON follows (platform)')

        # 通知记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,  -- 'stock_add', 'stock_remove', 'rebalance'
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # 全局股票快照表（按平台用户存储）
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS global_stock_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,           -- 平台标识，如 'xueqiu'
                platform_user_id TEXT NOT NULL,   -- 平台用户ID
                stock_symbol TEXT NOT NULL,
                stock_name TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(platform, platform_user_id, stock_symbol)
            )
        ''')

        # 创建索引
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_global_stocks_platform_user ON global_stock_snapshots (platform, platform_user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_global_stocks_symbol ON global_stock_snapshots (stock_symbol)')

        # 全局组合调仓快照表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS global_rebalance_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,           -- 平台标识，如 'xueqiu'
                target_symbol TEXT NOT NULL,      -- 目标ID（如组合symbol）
                rebalance_id TEXT NOT NULL,       -- 调仓记录ID
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(platform, target_symbol, rebalance_id)
            )
        ''')

        # 创建索引
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_global_rebalance_platform ON global_rebalance_snapshots (platform, target_symbol)')

        # 用户股票订阅表（记录用户关注的股票快照）
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_stock_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                platform_user_id TEXT NOT NULL,
                stock_symbol TEXT NOT NULL,
                subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, platform, platform_user_id, stock_symbol)
            )
        ''')

        # 用户组合调仓订阅表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_rebalance_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                target_symbol TEXT NOT NULL,
                rebalance_id TEXT NOT NULL,
                subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, platform, target_symbol, rebalance_id)
            )
        ''')

        db.commit()


@app.teardown_appcontext
def close_db():
    """关闭数据库连接"""
    if hasattr(g, 'db'):
        g.db.close()


# ========== JWT认证 ==========
def generate_token(phone, user_id):
    """生成JWT token"""
    payload = {
        'phone': phone,
        'user_id': user_id,
        'exp': datetime.now() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


def verify_token(token):
    """验证JWT token - 增加数据库用户有效性检查"""
    try:
        # 解码token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        # 从payload中获取用户信息
        user_id = payload.get('user_id')
        phone = payload.get('phone')

        if not user_id or not phone:
            return None

        # 检查数据库中用户是否存在且有效
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'SELECT id, phone FROM users WHERE id = ? AND phone = ?',
            (user_id, phone)
        )
        user = cursor.fetchone()

        if not user:
            app.logger.warning(f"无效的用户token: user_id={user_id}, phone={phone}")
            return None

        # 关闭数据库连接
        cursor.close()

        # 返回payload
        return payload

    except jwt.ExpiredSignatureError:
        app.logger.warning("JWT token已过期")
        return None
    except jwt.InvalidTokenError as e:
        app.logger.warning(f"无效的JWT token: {str(e)}")
        return None
    except Exception as e:
        app.logger.error(f"验证JWT token时发生错误: {str(e)}")
        return None


# ========== 认证装饰器 ==========
def token_required(f):
    """JWT认证装饰器"""

    def decorator(*args, **kwargs):
        token = None

        # 从header获取token
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # 将用户信息添加到request上下文
        request.user_id = payload['user_id']
        request.phone = payload['phone']

        return f(*args, **kwargs)

    decorator.__name__ = f.__name__
    return decorator


# ========== 辅助函数 ==========
def validate_follow_params(data, follow_type):
    """验证关注参数"""
    if not data:
        return False, "参数不能为空"

    if follow_type == FOLLOW_TYPE_USER:
        if not data.get('target_id') or not data.get('target_name'):
            return False, "用户ID和名称不能为空"
    elif follow_type == FOLLOW_TYPE_CUBE:
        if not data.get('target_id') or not data.get('target_name'):
            return False, "组合ID和名称不能为空"
    else:
        return False, "不支持的关注类型"

    return True, ""


def get_follow_by_id(follow_id, user_id):
    """根据ID获取关注记录"""
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        'SELECT * FROM follows WHERE id = ? AND user_id = ?',
        (follow_id, user_id)
    )

    return cursor.fetchone()


def delete_follow_snapshots(follow_id, follow_type):
    """删除关注相关的订阅数据"""
    db = get_db()
    cursor = db.cursor()

    try:
        # 获取关注记录
        cursor.execute('SELECT * FROM follows WHERE id = ?', (follow_id,))
        f = cursor.fetchone()

        if not f:
            return

        user_id = f['user_id']
        platform = f['platform']
        target_id = f['target_id']

        if follow_type == FOLLOW_TYPE_USER:
            # 删除用户对该雪球用户的所有股票订阅
            cursor.execute(
                '''DELETE FROM user_stock_subscriptions 
                   WHERE user_id = ? AND platform = ? AND platform_user_id = ?''',
                (user_id, platform, target_id)
            )
        elif follow_type == FOLLOW_TYPE_CUBE:
            # 删除用户对该组合的所有调仓订阅
            cursor.execute(
                '''DELETE FROM user_rebalance_subscriptions 
                   WHERE user_id = ? AND platform = ? AND target_symbol = ?''',
                (user_id, platform, target_id)
            )

        # 注意：这里不删除全局快照，因为其他用户可能还在关注
        db.commit()

    except Exception as e:
        db.rollback()
        app.logger.error(f"删除关注订阅失败: {str(e)}")


def cleanup_expired_data():
    """定期清理过期数据"""
    db = get_db()
    cursor = db.cursor()

    try:
        # 清理30天前且没有用户订阅的全局股票快照
        cursor.execute('''
            DELETE FROM global_stock_snapshots 
            WHERE last_updated < datetime('now', '-30 days')
            AND NOT EXISTS (
                SELECT 1 FROM user_stock_subscriptions 
                WHERE platform = global_stock_snapshots.platform 
                  AND platform_user_id = global_stock_snapshots.platform_user_id 
                  AND stock_symbol = global_stock_snapshots.stock_symbol
            )
        ''')

        deleted_stocks = cursor.rowcount

        # 清理30天前且没有用户订阅的全局调仓快照
        cursor.execute('''
            DELETE FROM global_rebalance_snapshots 
            WHERE last_updated < datetime('now', '-30 days')
            AND NOT EXISTS (
                SELECT 1 FROM user_rebalance_subscriptions 
                WHERE platform = global_rebalance_snapshots.platform 
                  AND target_symbol = global_rebalance_snapshots.target_symbol 
                  AND rebalance_id = global_rebalance_snapshots.rebalance_id
            )
        ''')

        deleted_rebalances = cursor.rowcount

        db.commit()

        if deleted_stocks > 0 or deleted_rebalances > 0:
            app.logger.info(f"清理了{deleted_stocks}个过期股票快照和{deleted_rebalances}个过期调仓快照")

    except Exception as e:
        db.rollback()
        app.logger.error(f"清理过期数据失败: {str(e)}")


# ========== API路由 ==========
# 删除原来的 /api/register 和 /api/login 路由
# 添加新的 /api/auth 合并接口

@app.route('/api/auth', methods=['POST'])
def auth():
    """合并注册/登录接口"""
    global action
    data = request.get_json()

    if not data or not data.get('phone') or not data.get('password'):
        return jsonify({'error': '手机号和密码不能为空'}), 400

    phone = data['phone']
    password = data['password']

    # 验证手机号格式
    if not re.match(r'^1[3-9]\d{9}$', phone):
        return jsonify({'error': '手机号格式不正确'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # 查询用户是否已存在
        cursor.execute('SELECT id, password_hash FROM users WHERE phone = ?', (phone,))
        user = cursor.fetchone()

        if user:
            # 用户存在，验证密码（登录）
            if not check_password_hash(user['password_hash'], password):
                return jsonify({'error': '密码错误'}), 401

            # 更新最后登录时间
            cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user['id'],)
            )

            action = '登录'
            user_id = user['id']

        else:
            # 用户不存在，创建新用户（注册）
            password_hash = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (phone, password_hash) VALUES (?, ?)',
                (phone, password_hash)
            )

            action = '注册'
            user_id = cursor.lastrowid

        # 生成token
        token = generate_token(phone, user_id)

        db.commit()

        return jsonify({
            'message': f'{action}成功',
            'token': token,
            'user_id': user_id,
            'action': action
        })

    except Exception as e:
        db.rollback()
        app.logger.error(f"{action}失败: {str(e)}")

        if 'UNIQUE constraint' in str(e):
            return jsonify({'error': '用户已存在'}), 400
        else:
            return jsonify({'error': f'{action}失败'}), 500


@app.route('/api/search/user', methods=['GET'])
@token_required
def search_user():
    """搜索雪球用户"""
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    count = request.args.get('count', 20, type=int)

    if not query:
        return jsonify({'error': '搜索关键词不能为空'}), 400

    try:
        # 调用雪球搜索API
        search_url = "https://xueqiu.com/query/v1/search/user.json"
        params = {
            'q': query,
            'page': page,
            'count': count
        }

        response = requests.get(search_url, params=params, headers=XQ_HEADERS)

        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'users': data.get('list', []),
                'total': data.get('count', 0)
            })
        else:
            return jsonify({'error': '搜索失败'}), 500

    except Exception as e:
        app.logger.error(f"搜索用户失败: {str(e)}")
        return jsonify({'error': '搜索失败'}), 500


@app.route('/api/search/cube', methods=['GET'])
@token_required
def search_cube():
    """搜索雪球组合"""
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    count = request.args.get('count', 20, type=int)

    if not query:
        return jsonify({'error': '搜索关键词不能为空'}), 400

    try:
        # 调用雪球组合搜索API
        search_url = "https://xueqiu.com/query/v1/search/cube.json"
        params = {
            'q': query,
            'page': page,
            'count': count
        }

        response = requests.get(search_url, params=params, headers=XQ_HEADERS)

        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'cubes': data.get('list', []),
                'total': data.get('count', 0)
            })
        else:
            return jsonify({'error': '搜索失败'}), 500

    except Exception as e:
        app.logger.error(f"搜索组合失败: {str(e)}")
        return jsonify({'error': '搜索失败'}), 500


@app.route('/api/follow', methods=['POST'])
@token_required
def follow():
    """通用关注接口"""
    data = request.get_json()

    if not data or not data.get('type'):
        return jsonify({'error': '参数不完整'}), 400

    follow_type = data['type']
    platform = data.get('platform', 'xueqiu')  # 默认为雪球平台
    user_id = request.user_id

    # 验证参数
    is_valid, error_msg = validate_follow_params(data, follow_type)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # 检查是否已关注
        cursor.execute(
            '''SELECT id FROM follows 
               WHERE user_id = ? AND follow_type = ? AND platform = ? AND target_id = ?''',
            (user_id, follow_type, platform, data['target_id'])
        )
        if cursor.fetchone():
            return jsonify({'error': '已关注该目标'}), 400

        # 构建额外信息
        extra_info = {}
        if follow_type == FOLLOW_TYPE_USER:
            extra_info = {
                'xueqiu_uid': data['target_id']
            }
        elif follow_type == FOLLOW_TYPE_CUBE:
            extra_info = {
                'cube_symbol': data['target_id']
            }

        # 添加关注
        cursor.execute(
            '''INSERT INTO follows 
               (user_id, follow_type, platform, target_id, target_name, extra_info) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, follow_type, platform, data['target_id'],
             data['target_name'], json.dumps(extra_info))
        )

        db.commit()

        return jsonify({
            'message': '关注成功',
            'follow_id': cursor.lastrowid,
            'type': follow_type,
            'platform': platform
        })

    except Exception as e:
        db.rollback()
        app.logger.error(f"关注失败: {str(e)}")
        return jsonify({'error': '关注失败'}), 500


@app.route('/api/unfollow/<int:follow_id>', methods=['DELETE'])
@token_required
def unfollow(follow_id):
    """通用取消关注接口"""
    user_id = request.user_id

    db = get_db()
    cursor = db.cursor()

    try:
        # 获取关注记录
        f = get_follow_by_id(follow_id, user_id)
        if not f:
            return jsonify({'error': '未找到关注记录或无权操作'}), 404

        # 删除相关快照数据
        delete_follow_snapshots(follow_id, f['follow_type'])

        # 删除关注记录
        cursor.execute('DELETE FROM follows WHERE id = ?', (follow_id,))

        db.commit()
        app.logger.info(f"用户{user_id}取消关注: ")
        return jsonify({
            'message': '取消关注成功',
            'follow_id': follow_id,
            'type': f['follow_type']
        })

    except Exception as e:
        db.rollback()
        app.logger.error(f"取消关注失败: {str(e)}")
        return jsonify({'error': '取消关注失败'}), 500


@app.route('/api/follows', methods=['GET'])
@token_required
def get_follows():
    """获取关注列表（支持按类型筛选）"""
    user_id = request.user_id
    follow_type = request.args.get('type', '')  # 可选：user/cube
    platform = request.args.get('platform', '')  # 可选：xueqiu/其他

    db = get_db()
    cursor = db.cursor()

    # 构建查询条件
    conditions = ['user_id = ?']
    params = [user_id]

    if follow_type:
        conditions.append('follow_type = ?')
        params.append(follow_type)

    if platform:
        conditions.append('platform = ?')
        params.append(platform)

    # 执行查询
    where_clause = ' AND '.join(conditions) if conditions else '1=1'
    query = f'''
        SELECT id, follow_type, platform, target_id, target_name, 
               extra_info, created_at 
        FROM follows 
        WHERE {where_clause}
        ORDER BY created_at DESC
    '''

    cursor.execute(query, params)
    follows = []

    for row in cursor.fetchall():
        f = dict(row)
        # 解析额外信息
        if f['extra_info']:
            try:
                f['extra_info'] = json.loads(f['extra_info'])
            except:
                f['extra_info'] = {}
        follows.append(f)

    # 按类型分组
    follows_by_type = {}
    for f in follows:
        follow_type = f['follow_type']
        if follow_type not in follows_by_type:
            follows_by_type[follow_type] = []
        follows_by_type[follow_type].append(f)

    return jsonify({
        'follows': follows,
        'grouped_by_type': follows_by_type,
        'total': len(follows)
    })


@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications():
    """获取通知列表"""
    user_id = request.user_id
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (page - 1) * limit

    db = get_db()
    cursor = db.cursor()

    # 获取通知总数
    cursor.execute(
        'SELECT COUNT(*) as total FROM notifications WHERE user_id = ?',
        (user_id,)
    )
    total = cursor.fetchone()['total']

    # 获取通知列表
    cursor.execute(
        '''SELECT id, type, title, content, is_read, created_at 
           FROM notifications 
           WHERE user_id = ? 
           ORDER BY created_at DESC 
           LIMIT ? OFFSET ?''',
        (user_id, limit, offset)
    )
    notifications = [dict(row) for row in cursor.fetchall()]

    return jsonify({
        'notifications': notifications,
        'total': total,
        'page': page,
        'total_pages': (total + limit - 1) // limit
    })


@app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
@token_required
def mark_notification_read(notification_id):
    """标记通知为已读"""
    user_id = request.user_id

    db = get_db()
    cursor = db.cursor()

    # 验证权限
    cursor.execute(
        'SELECT id FROM notifications WHERE id = ? AND user_id = ?',
        (notification_id, user_id)
    )
    if not cursor.fetchone():
        return jsonify({'error': '未找到通知或无权操作'}), 404

    # 标记为已读
    cursor.execute(
        'UPDATE notifications SET is_read = 1 WHERE id = ?',
        (notification_id,)
    )

    db.commit()

    return jsonify({'message': '标记为已读成功'})


# ========== 监控服务 ==========
class XueqiuMonitor:
    """雪球监控服务"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(XQ_HEADERS)
        self.stock_url = "https://stock.xueqiu.com/v5/stock/portfolio/stock/list.json"
        self.cube_url = "https://xueqiu.com/cubes/rebalancing/history.json"
        self.interval = app.config['INTERVAL']
        self.running = False

    def get_stock_data(self, xueqiu_uid):
        """获取用户股票数据"""
        params = {
            "pid": "-1",
            "category": "1",
            "size": "1000",
            "uid": xueqiu_uid
        }
        try:
            response = self.session.get(self.stock_url, params=params)
            response.raise_for_status()
            data = response.json()
            return data.get('data', {}).get('stocks', [])
        except Exception as e:
            app.logger.error(f"获取股票数据失败 {xueqiu_uid}: {str(e)}")
            return []

    def get_cube_data(self, cube_symbol):
        """获取组合调仓数据"""
        params = {
            "count": 20,
            "page": 1,
            "cube_symbol": cube_symbol
        }
        try:
            response = self.session.get(self.cube_url, params=params)
            response.raise_for_status()
            data = response.json()
            return data.get('list', [])
        except Exception as e:
            app.logger.error(f"获取组合数据失败 {cube_symbol}: {str(e)}")
            return []

    def check_stock_changes(self, platform, platform_user_id, target_name):
        """检查股票变化 - 使用全局快照"""
        db = get_db()
        cursor = db.cursor()

        try:
            # 开始事务
            cursor.execute('BEGIN TRANSACTION')

            # 获取当前股票列表（目前只支持雪球平台）
            if platform == 'xueqiu':
                current_stocks = self.get_stock_data(platform_user_id)
            else:
                # 其他平台的股票数据获取逻辑可以在这里扩展
                current_stocks = []

            if not current_stocks:
                db.rollback()
                return

            # 从全局快照获取历史记录
            cursor.execute(
                '''SELECT stock_symbol, stock_name 
                   FROM global_stock_snapshots 
                   WHERE platform = ? AND platform_user_id = ?''',
                (platform, platform_user_id)
            )
            previous_stocks = {row['stock_symbol']: row['stock_name'] for row in cursor.fetchall()}

            # 获取当前股票集合
            current_symbols = {}
            for stock in current_stocks:
                symbol = stock.get('symbol')
                if symbol:
                    current_symbols[symbol] = stock.get('name', '')

            # 找出新增的股票
            new_symbols = current_symbols.keys() - previous_stocks.keys()
            for symbol in new_symbols:
                stock_name = current_symbols[symbol]

                # 插入到全局快照（如果不存在）
                cursor.execute(
                    '''INSERT OR IGNORE INTO global_stock_snapshots 
                       (platform, platform_user_id, stock_symbol, stock_name) 
                       VALUES (?, ?, ?, ?)''',
                    (platform, platform_user_id, symbol, stock_name)
                )

                # 为所有关注该平台用户的用户创建通知
                cursor.execute(
                    '''SELECT f.user_id 
                       FROM follows f
                       WHERE f.follow_type = ? 
                         AND f.platform = ? 
                         AND f.target_id = ?''',
                    (FOLLOW_TYPE_USER, platform, platform_user_id)
                )

                for row in cursor.fetchall():
                    user_id = row['user_id']

                    # 订阅新增的股票（如果用户还没有订阅）
                    cursor.execute(
                        '''INSERT OR IGNORE INTO user_stock_subscriptions 
                           (user_id, platform, platform_user_id, stock_symbol) 
                           VALUES (?, ?, ?, ?)''',
                        (user_id, platform, platform_user_id, symbol)
                    )

                    # 只有非首次检查才发通知
                    if previous_stocks:
                        title = f"{target_name} 新增自选"
                        content = f"股票: {stock_name} ({symbol})"
                        cursor.execute(
                            '''INSERT INTO notifications 
                               (user_id, type, title, content) 
                               VALUES (?, ?, ?, ?)''',
                            (user_id, 'stock_add', title, content)
                        )
                        app.logger.info(f"用户{user_id}: {title} - {content}")

            # 找出删除的股票
            removed_symbols = previous_stocks.keys() - current_symbols.keys()
            for symbol in removed_symbols:
                stock_name = previous_stocks[symbol]

                # 从全局快照中删除
                cursor.execute(
                    'DELETE FROM global_stock_snapshots WHERE platform = ? AND platform_user_id = ? AND stock_symbol = ?',
                    (platform, platform_user_id, symbol)
                )

                # 为所有订阅了该股票的用户创建通知
                cursor.execute(
                    '''SELECT user_id FROM user_stock_subscriptions 
                       WHERE platform = ? AND platform_user_id = ? AND stock_symbol = ?''',
                    (platform, platform_user_id, symbol)
                )

                for row in cursor.fetchall():
                    user_id = row['user_id']
                    title = f"{target_name} 移除自选"
                    content = f"股票: {stock_name} ({symbol})"
                    cursor.execute(
                        '''INSERT INTO notifications 
                           (user_id, type, title, content) 
                           VALUES (?, ?, ?, ?)''',
                        (user_id, 'stock_remove', title, content)
                    )
                    app.logger.info(f"用户{user_id}: {title} - {content}")

                # 删除所有用户的订阅
                cursor.execute(
                    'DELETE FROM user_stock_subscriptions WHERE platform = ? AND platform_user_id = ? AND stock_symbol = ?',
                    (platform, platform_user_id, symbol)
                )

            # 提交事务
            db.commit()

        except Exception as e:
            # 发生错误时回滚事务
            db.rollback()
            app.logger.error(f"检查股票变化失败 {platform}/{platform_user_id}: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())

    def check_cube_rebalance(self, platform, target_symbol, target_name):
        """检查组合调仓 - 使用全局快照"""
        db = get_db()
        cursor = db.cursor()

        try:
            # 开始事务
            cursor.execute('BEGIN TRANSACTION')

            # 获取组合调仓历史（目前只支持雪球平台）
            if platform == 'xueqiu':
                rebalance_list = self.get_cube_data(target_symbol)
            else:
                # 其他平台的调仓数据获取逻辑可以在这里扩展
                rebalance_list = []

            if not rebalance_list:
                db.rollback()
                return

            # 获取最新的调仓记录
            latest_rebalance = rebalance_list[0]
            rebalance_id = str(latest_rebalance.get('id', ''))

            if not rebalance_id:
                db.rollback()
                return

            # 检查是否已记录过这个调仓
            cursor.execute(
                'SELECT id FROM global_rebalance_snapshots WHERE platform = ? AND target_symbol = ? AND rebalance_id = ?',
                (platform, target_symbol, rebalance_id)
            )

            if not cursor.fetchone():
                # 记录到全局快照
                cursor.execute(
                    '''INSERT OR IGNORE INTO global_rebalance_snapshots 
                       (platform, target_symbol, rebalance_id) 
                       VALUES (?, ?, ?)''',
                    (platform, target_symbol, rebalance_id)
                )

                # 解析调仓详情
                histories = latest_rebalance.get('rebalancing_histories', [])
                for history in histories:
                    stock_symbol = history.get('stock_symbol', '')
                    stock_name = history.get('stock_name', '')
                    price = history.get('price', 0)
                    prev_weight = history.get('prev_weight_adjusted', 0) or 0
                    target_weight = history.get('target_weight', 0)

                    if stock_symbol:
                        # 为所有关注该组合的用户创建通知
                        cursor.execute(
                            '''SELECT f.user_id 
                               FROM follows f
                               WHERE f.follow_type = ? 
                                 AND f.platform = ? 
                                 AND f.target_id = ?''',
                            (FOLLOW_TYPE_CUBE, platform, target_symbol)
                        )

                        for row in cursor.fetchall():
                            user_id = row['user_id']
                            title = f"{target_name} 调仓"
                            content = f"{stock_name}({stock_symbol}): {prev_weight:.2f}% → {target_weight:.2f}% @ {price}"
                            cursor.execute(
                                '''INSERT INTO notifications 
                                   (user_id, type, title, content) 
                                   VALUES (?, ?, ?, ?)''',
                                (user_id, 'rebalance', title, content)
                            )
                            app.logger.info(f"用户{user_id}: {title} - {content}")

                        # 订阅这个调仓记录（为所有关注该组合的用户）
                        cursor.execute(
                            '''SELECT f.user_id 
                               FROM follows f
                               WHERE f.follow_type = ? 
                                 AND f.platform = ? 
                                 AND f.target_id = ?''',
                            (FOLLOW_TYPE_CUBE, platform, target_symbol)
                        )

                        for row in cursor.fetchall():
                            user_id = row['user_id']
                            cursor.execute(
                                '''INSERT OR IGNORE INTO user_rebalance_subscriptions 
                                   (user_id, platform, target_symbol, rebalance_id) 
                                   VALUES (?, ?, ?, ?)''',
                                (user_id, platform, target_symbol, rebalance_id)
                            )

                db.commit()
            else:
                db.rollback()

        except Exception as e:
            # 发生错误时回滚事务
            db.rollback()
            app.logger.error(f"检查组合调仓失败 {platform}/{target_symbol}: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())

    def monitor_loop(self):
        """监控循环"""
        app.logger.info("雪球监控服务启动")

        while self.running:
            try:
                with app.app_context():
                    db = get_db()
                    cursor = db.cursor()

                    # 获取所有关注的用户
                    cursor.execute('''
                        SELECT f.platform, f.target_id, f.target_name, f.extra_info, u.id as user_id
                        FROM follows f
                        JOIN users u ON f.user_id = u.id
                        WHERE f.follow_type = ?
                    ''', (FOLLOW_TYPE_USER,))

                    followed_users = cursor.fetchall()

                    # 检查每个关注的用户
                    for row in followed_users:
                        try:
                            self.check_stock_changes(
                                row['platform'],  # 平台标识
                                row['target_id'],  # 平台用户ID
                                row['target_name']
                            )
                        except Exception as e:
                            app.logger.error(f"检查用户{row['target_name']}失败: {str(e)}")

                    # 获取所有关注的组合
                    cursor.execute('''
                        SELECT f.platform, f.target_id, f.target_name, f.extra_info, u.id as user_id
                        FROM follows f
                        JOIN users u ON f.user_id = u.id
                        WHERE f.follow_type = ?
                    ''', (FOLLOW_TYPE_CUBE,))

                    followed_cubes = cursor.fetchall()

                    # 检查每个关注的组合
                    for row in followed_cubes:
                        try:
                            self.check_cube_rebalance(
                                row['platform'],  # 平台标识
                                row['target_id'],  # 目标ID
                                row['target_name']
                            )
                        except Exception as e:
                            app.logger.error(f"检查组合{row['target_name']}失败: {str(e)}")

                    db.close()

                # 等待下一次检查
                time.sleep(self.interval)

            except Exception as e:
                app.logger.error(f"监控循环出错: {str(e)}")
                time.sleep(self.interval)

    def start(self):
        """启动监控服务"""
        if not self.running:
            self.running = True
            monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            monitor_thread.start()

    def stop(self):
        """停止监控服务"""
        self.running = False


# ========== 启动监控服务 ==========
monitor = XueqiuMonitor()


def before_first_request():
    """在第一个请求前初始化"""
    # 初始化数据库
    init_db()

    # 启动监控服务
    monitor.start()
    app.logger.info("监控服务已启动")


# ========== 日志配置 ==========
def setup_logging():
    """配置日志"""
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # 文件日志
    file_handler = RotatingFileHandler(
        'logs/xueqiu_monitor.log',
        maxBytes=1024 * 1024 * 10,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    # 控制台日志
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    app.logger.addHandler(console_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('雪球监控后台服务启动')


# ========== 主程序入口 ==========
if __name__ == '__main__':
    setup_logging()
    init_db()
    monitor.start()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )

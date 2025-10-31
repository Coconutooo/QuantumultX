import base64
import requests
from urllib.parse import urlparse, parse_qs, unquote
import re

class VLessToQuantumultXParser:
    def __init__(self):
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def fetch_subscription(self, subscription_url):
        """从订阅链接获取内容"""
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(subscription_url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"获取订阅失败: {e}")
            return None
    
    def parse_subscription(self, subscription_url):
        """主解析函数"""
        print("正在获取订阅内容...")
        raw_content = self.fetch_subscription(subscription_url)
        
        if not raw_content:
            return None
        
        # 解码Base64内容
        try:
            decoded_content = base64.b64decode(raw_content).decode('utf-8')
        except:
            decoded_content = raw_content
        
        # 解析节点
        nodes = []
        for line in decoded_content.splitlines():
            line = line.strip()
            if line.startswith('vless://'):
                node = self.parse_vless_url(line)
                if node:
                    nodes.append(node)
        
        return nodes
    
    def parse_vless_url(self, vless_url):
        """解析单个VLess URL"""
        try:
            parsed = urlparse(vless_url)
            params = parse_qs(parsed.query)
            
            # 基础信息
            uuid = parsed.username
            server = parsed.hostname
            port = parsed.port
            
            # 节点配置
            node_config = {
                'type': 'vless',
                'uuid': uuid,
                'server': server,
                'port': port,
                'remark': unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}",
                'encryption': params.get('encryption', ['none'])[0],
                'flow': params.get('flow', [''])[0],
                'network': params.get('type', ['tcp'])[0],
                'security': params.get('security', [''])[0],
                'sni': params.get('sni', [''])[0],
                'host': params.get('host', [''])[0],
                'path': unquote(params.get('path', [''])[0]),
                'serviceName': params.get('serviceName', [''])[0],
                'headerType': params.get('headerType', ['none'])[0]
            }
            
            return node_config
            
        except Exception as e:
            print(f"解析VLess URL失败: {e}")
            return None
    
    def vless_to_vmess(self, vless_config):
        """
        将 VLESS 配置转换为 VMess 配置
        返回: 字符串，Quantumult X 格式的 VMess 配置
        """
        try:
            # 基础信息
            vmess_parts = [
                f"vmess={vless_config['server']}:{vless_config['port']}",
                f"method=aes-128-gcm",  # VMess 默认加密方式
                f"password={vless_config['uuid']}",
            ]
            
            # 传输协议和混淆处理
            network = vless_config.get('network', 'tcp')
            security = vless_config.get('security', '')
            
            # 处理 WebSocket
            if network == 'ws':
                if security == 'tls':
                    vmess_parts.append("obfs=wss")
                else:
                    vmess_parts.append("obfs=ws")
                
                # 添加 WebSocket 路径和 Host
                if vless_config.get('path'):
                    vmess_parts.append(f"obfs-uri={vless_config['path']}")
                if vless_config.get('host'):
                    vmess_parts.append(f"obfs-host={vless_config['host']}")
                elif vless_config.get('sni'):
                    vmess_parts.append(f"obfs-host={vless_config['sni']}")
            
            # 处理纯 TLS (TCP over TLS)
            elif security == 'tls' and network == 'tcp':
                vmess_parts.append("obfs=over-tls")
                if vless_config.get('sni'):
                    vmess_parts.append(f"obfs-host={vless_config['sni']}")
                elif vless_config.get('host'):
                    vmess_parts.append(f"obfs-host={vless_config['host']}")
            
            # 处理 gRPC
            elif network == 'grpc':
                vmess_parts.append("obfs=grpc")
                if vless_config.get('serviceName'):
                    vmess_parts.append(f"obfs-host={vless_config['serviceName']}")
                elif vless_config.get('host'):
                    vmess_parts.append(f"obfs-host={vless_config['host']}")
            
            # 处理 HTTP
            elif network == 'http':
                vmess_parts.append("obfs=http")
                if vless_config.get('host'):
                    vmess_parts.append(f"obfs-host={vless_config['host']}")
                if vless_config.get('path'):
                    vmess_parts.append(f"obfs-uri={vless_config['path']}")
            
            # 添加 TLS 1.3 支持
            if security == 'tls':
                vmess_parts.append("tls13=true")
            
            # 添加基本参数
            vmess_parts.extend([
                "fast-open=false",
                "udp-relay=false",
                f"tag={vless_config['remark']}-VMess"  # 添加VMess标识
            ])
            
            return ", ".join(vmess_parts)
            
        except Exception as e:
            print(f"VLESS转VMess失败: {e}")
            return None
    
    def convert_to_vless_original(self, node):
        """保持原来的VLESS转换（供参考）"""
        try:
            config_parts = [
                f"vless={node['server']}:{node['port']}",
                f"password={node['uuid']}",
                "fast-open=false",
                "udp-relay=false"
            ]
            
            if node['encryption'] == 'none':
                config_parts.append("method=none")
            else:
                config_parts.append("method=chacha20-poly1305")
            
            # TLS配置
            if node['security'] == 'tls':
                if node['network'] == 'ws':
                    config_parts.append("obfs=wss")
                else:
                    config_parts.append("obfs=over-tls")
                
                if node['sni']:
                    config_parts.append(f"obfs-host={node['sni']}")
                elif node['host']:
                    config_parts.append(f"obfs-host={node['host']}")
                
                config_parts.append("tls13=true")
            
            # WebSocket配置
            elif node['network'] == 'ws' and node['security'] != 'tls':
                config_parts.append("obfs=ws")
                if node['host']:
                    config_parts.append(f"obfs-host={node['host']}")
            
            # 路径配置
            if node['path'] and node['network'] in ['ws', 'http']:
                config_parts.append(f"obfs-uri={node['path']}")
            
            # 流控
            if node['flow']:
                config_parts.append(f"flow={node['flow']}")
            
            config_parts.append(f"tag={node['remark']}")
            
            return ", ".join(config_parts)
            
        except Exception as e:
            print(f"转换VLESS配置失败: {e}")
            return None
    
    def save_config(self, configs, filename):
        """保存配置到文件"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for config in configs:
                    f.write(config + "\n")
            print(f"✅ 配置已保存到: {filename}")
            return True
        except Exception as e:
            print(f"保存文件失败: {e}")
            return False

def main():
    parser = VLessToQuantumultXParser()
    
    # 你的订阅链接（更换为你的节点订阅链接）
    subscription_url = "https://bbq.strawberrygummy.com/api/v1/client/subscribe?token=你的token"
    
    print("开始解析VLess订阅...")
    nodes = parser.parse_subscription(subscription_url)
    
    if nodes:
        print(f"\n✅ 成功解析 {len(nodes)} 个节点")
        print("=" * 60)
        
        # 生成VMess配置（推荐，兼容性更好）
        vmess_configs = []
        print("VMess 配置（推荐）:")
        print("-" * 40)
        for i, node in enumerate(nodes, 1):
            config = parser.vless_to_vmess(node)
            if config:
                print(f"{i}. {config}")
                vmess_configs.append(config)
        
        # 保存VMess配置
        if vmess_configs:
            parser.save_config(vmess_configs, "VMess_QuantumultX.conf")
            print(f"\n📱 VMess配置已保存，请在QuantumultX中导入 VMess_QuantumultX.conf")
        
        # 可选：也生成VLESS配置供参考
        vless_configs = []
        print("\n" + "=" * 60)
        print("VLESS 配置（供参考，可能不兼容）:")
        print("-" * 40)
        for i, node in enumerate(nodes, 1):
            config = parser.convert_to_vless_original(node)
            if config:
                print(f"{i}. {config}")
                vless_configs.append(config)
        
        if vless_configs:
            parser.save_config(vless_configs, "VLESS_QuantumultX.conf")
            print(f"\n⚠️  VLESS配置已保存，如果VMess不工作可尝试导入 VLESS_QuantumultX.conf")
        
        print("\n" + "=" * 60)
        print("使用建议:")
        print("1. 📋 优先使用 VMess_QuantumultX.conf (兼容性最好)")
        print("2. 🔧 如果VMess不工作，再尝试 VLESS_QuantumultX.conf")
        print("3. 📱 在QuantumultX中: 设置 → 服务器 → 右上角+号 → 从文件导入")
        
    else:
        print("❌ 解析失败，请检查订阅链接")

if __name__ == "__main__":
    main()
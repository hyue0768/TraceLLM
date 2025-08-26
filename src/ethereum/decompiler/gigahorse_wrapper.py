import subprocess
import os
import re
import signal
import time
from contextlib import contextmanager

def clean_ansi_codes(text):
    """移除所有ANSI转义序列"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@contextmanager
def timeout_context(seconds):
    """超时上下文管理器"""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"操作超时 ({seconds}秒)")
    
    # 设置信号处理器
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # 恢复原来的信号处理器
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def decompile_bytecode(bytecode, timeout_minutes=30):
    """修改后的反编译函数（直接返回反编译结果，支持超时）"""
    timeout_seconds = timeout_minutes * 60  # 转换为秒
    
    print(f"开始反编译字节码（超时时间：{timeout_minutes}分钟）...")
    start_time = time.time()
    
    try:
        with timeout_context(timeout_seconds):
            result = subprocess.run(
                ["panoramix", bytecode],
                capture_output=True,
                text=True,
                env={**os.environ, 'TERM': 'dumb'},
                timeout=timeout_seconds  # subprocess自身的超时
            )
            
            elapsed_time = time.time() - start_time
            print(f"反编译完成，耗时：{elapsed_time:.2f}秒")
        
            if result.returncode == 0:
                return clean_ansi_codes(result.stdout)
            print(f"反编译失败: {result.stderr}")
            return None
            
    except TimeoutError as e:
        elapsed_time = time.time() - start_time
        print(f"反编译超时（{elapsed_time:.2f}秒），跳过该合约")
        print(f"超时原因：{str(e)}")
        return None
        
    except subprocess.TimeoutExpired:
        elapsed_time = time.time() - start_time
        print(f"反编译进程超时（{elapsed_time:.2f}秒），跳过该合约")
        return None
        
    except Exception as e:
        elapsed_time = time.time() - start_time
        print(f"反编译错误（{elapsed_time:.2f}秒）: {str(e)}")
        return None
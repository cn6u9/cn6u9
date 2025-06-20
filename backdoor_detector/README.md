# 扫描单个文件
python3 backdoor_detector.py suspicious_script.py

# 扫描整个目录
python3 backdoor_detector.py /root/ -o out.json

# 使用白名单并保存结果
python3 backdoor_detector.py /path/to/project/ --whitelist my_whitelist.json --output results.json
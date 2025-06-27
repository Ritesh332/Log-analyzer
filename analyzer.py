from utils import load_blacklist, export_incidents
import pandas as pd
import matplotlib.pyplot as plt
import re

# Regex Patterns
apache_pattern = re.compile(r'(?P<ip>\S+) .* \[(?P<time>.*?)\] "(?P<method>\S+) (?P<url>\S+) .*" (?P<status>\d+)')
ssh_pattern = re.compile(r'(?P<time>\w{3} +\d+ \d+:\d+:\d+).*sshd.*Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\S+)')

# Parse Apache Log
def parse_apache_log(file_path):
    data = []
    with open(file_path) as f:
        for line in f:
            match = apache_pattern.search(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

# Parse SSH Log
def parse_ssh_log(file_path):
    data = []
    with open(file_path) as f:
        for line in f:
            match = ssh_pattern.search(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

# Detect Brute Force Attacks
def detect_bruteforce(df):
    return df['ip'].value_counts()[df['ip'].value_counts() > 2].index.tolist()

# Visualize Top IPs
def visualize_access_by_ip(df):
    df['time'] = pd.to_datetime(df['time'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
    ip_counts = df['ip'].value_counts().head(10)
    ip_counts.plot(kind='bar', title='Top 10 IPs by Access')
    plt.tight_layout()
    plt.savefig('visualizations/access_patterns.png')

# Main Function
def main():
    apache_df = parse_apache_log('data/apache.log')
    ssh_df = parse_ssh_log('data/auth.log')

    ssh_threat_ips = detect_bruteforce(ssh_df)
    ssh_threats = ssh_df[ssh_df['ip'].isin(ssh_threat_ips)]
    ssh_threats.loc[:, 'threat_type'] = 'brute_force'

    blacklist_ips = load_blacklist()
    blacklist_hits = apache_df[apache_df['ip'].isin(blacklist_ips)]
    blacklist_hits.loc[:, 'threat_type'] = 'blacklist'

    all_threats = pd.concat([ssh_threats, blacklist_hits])
    export_incidents(all_threats)

    visualize_access_by_ip(apache_df)

if __name__ == "__main__":
    main()
